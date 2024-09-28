if (process.NODE_ENV !== "production") {
    require("dotenv").config()
}

const express = require("express");
const fs = require("fs");
const multer = require("multer"); // for handling file uploads
const path = require("path");
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors'); // Przydatne do obsługi CORS
const bcrypt = require('bcrypt');
const initializePassport = require('./passport-config.js')
const flash = require("express-flash")
const session = require("express-session")
const passport = require("passport")
const methodOverride = require("method-override")
const con = require('./dbConnection'); // Import połączenia z MySQL
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', // Zmień na adres swojego serwera SMTP
    port: 465,
    secure: true, // Zmien na true, jeśli używasz portu 465
    auth: {
        user: '', // Twój e-mail
        pass: '' // Twoje hasło
    }
});

initializePassport(
    passport,
    email => users.find(user => user.email === email),
    id => users.find(user => user.id === id)
)

const users = [];



const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.json({ limit: '50mb' })); // For JSON payloads
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true })); // For URL-encoded payloads

app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride("_method"))

app.use(passport.initialize());
app.use(passport.session());

// Wywołanie funkcji konfiguracji Passport
initializePassport(passport);

const crypto = require('crypto');

const secretKe1 = crypto.randomBytes(64).toString('hex');
console.log(secretKe1);


const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Pobieranie tokena z nagłówka
    console.log("Received token: ", token); // Logowanie tokena
    if (!token) return res.sendStatus(403); // Jeśli nie ma tokena

    jwt.verify(token, process.env.SESSION_SECRET3, (err, decoded) => {
        if (err) {
            console.error("Token verification error: ", err);
            return res.status(403).json({ message: 'Nieprawidłowy token' });
        }
        console.log("Decoded token: ", decoded); // Logowanie zawartości tokena
        req.userId = decoded.userId; // Przechowuj userId w obiekcie request
        next(); // Kontynuuj
    });
};

// Twój kod dla routingu i reszty logiki aplikacji
app.post("/login", checkNotAuth, (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return res.status(500).json({ message: 'Internal Server Error' }); // Handle server errors
        }
        if (!user) {
            // Send the error message from Passport
            return res.status(401).json({ message: info ? info.message : 'Login failed' }); // Send error to frontend
        }

        // Sprawdzenie, czy konto jest zweryfikowane
        if (!user.verified) {
            return res.status(403).json({ message: 'The account is not verified. Check your e-mail inbox.' });
        }

        req.logIn(user, (err) => {
            if (err) {
                return res.status(500).json({ message: 'Internal Server Error' }); // Handle server errors
            }

            req.session.userId = user.idUser; // Save user ID in session

            const token = jwt.sign(
                { userId: user.idUser, email: user.email },
                process.env.SESSION_SECRET3,
                { expiresIn: '1h' }
            );

            return res.json({
                message: "Zalogowano pomyślnie",
                token: token
            });
        });
    })(req, res, next);
});




app.post('/api/findUserById', authenticateToken, (req, res) => {
    // Sprawdź, czy użytkownik jest zalogowany
    if (!req.userId) {
        return res.status(401).json({ message: 'User not logged in' });
    }

    // Zwróć userId zalogowanego użytkownika z tokena
    const userId = req.userId; // Przechowujemy idUser z tokena
    console.log("Latest user ID:", userId);

    res.json({ id: userId }); // Zwracamy id użytkownika
});




app.post("/register", checkNotAuth, async (req, res) => {
    try {
        // Sprawdź, czy e-mail już istnieje
        const emailCheckSql = "SELECT * FROM uzytkownicy WHERE email = ?";
        con.query(emailCheckSql, [req.body.email], async (err, result) => {
            if (err) {
                console.error("Błąd podczas sprawdzania e-maila:", err);
                return res.redirect("/register.ejs");
            }

            if (result.length > 0) {
                // E-mail już istnieje, sprawdź status weryfikacji
                const existingUser = result[0];
                if (!existingUser.verified) {
                    // E-mail nie jest zweryfikowany, wyślij ponownie e-mail weryfikacyjny
                    const verificationToken = jwt.sign({ email: existingUser.email }, process.env.SESSION_SECRET3, { expiresIn: '1h' });
                    const verificationLink = `https://pokedex-3-ctc0.onrender.com/verify-email?token=${verificationToken}`;

                    const mailOptions = {
                        from: '',
                        to: existingUser.email,
                        subject: 'Weryfikacja e-maila',
                        text: `Kliknij w link, aby zweryfikować swój e-mail: ${verificationLink}`
                    };

                    transporter.sendMail(mailOptions, (error, info) => {
                        if (error) {
                            console.error("Błąd podczas wysyłania e-maila:", error);
                            return res.redirect("/register.ejs");
                        }
                        console.log("E-mail weryfikacyjny wysłany:", info.response);
                        return res.json({ emailExists: true, message: 'Wysłano ponownie e-mail weryfikacyjny.' });
                    });

                    return; // Zatrzymaj dalsze przetwarzanie
                } else {
                    // E-mail już zweryfikowany
                    return res.json({ emailExists: true, message: 'E-mail już istnieje i jest zweryfikowany.' });
                }
            }

            // Sprawdź, czy podano hasło
            if (!req.body.password) {
                return res.json({ error: 'Hasło jest wymagane' });
            }

            // Kontynuuj rejestrację
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            const newUser = {
                id: Date.now().toString(),
                name: req.body.name,
                email: req.body.email,
                password: hashedPassword,
            };

            const sql = "INSERT INTO uzytkownicy (idUser, name, email, password, verified) VALUES (?, ?, ?, ?, ?)";
            con.query(sql, [newUser.id, newUser.name, newUser.email, newUser.password, false], (err, result) => {
                if (err) {
                    console.error("Błąd podczas dodawania użytkownika:", err);
                    return res.redirect("/register.ejs");
                }
                console.log("Dodano 1 rekord");

                // Wygeneruj token weryfikacyjny
                const verificationToken = jwt.sign({ email: newUser.email }, process.env.SESSION_SECRET3, { expiresIn: '1h' });
                const verificationLink = `https://pokedex-3-ctc0.onrender.com/verify-email?token=${verificationToken}`;

                const mailOptions = {
                    from: '',
                    to: newUser.email,
                    subject: 'Weryfikacja e-maila',
                    text: `Kliknij w link, aby zweryfikować swój e-mail: ${verificationLink}`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error("Błąd podczas wysyłania e-maila:", error);
                        return res.redirect("/register.ejs");
                    }
                    console.log("E-mail weryfikacyjny wysłany:", info.response);
                });

                // Przekieruj do strony logowania
                res.redirect("/login.ejs");
            });
        });
    } catch (e) {
        console.log(e);
        res.redirect("/register.ejs");
    }
});




app.get("/verify-email", (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send('Brak tokenu weryfikacji');
    }

    // Zweryfikuj token
    jwt.verify(token, process.env.SESSION_SECRET3, (err, decoded) => {
        if (err) {
            return res.status(400).send('Token weryfikacji jest nieprawidłowy lub wygasł');
        }

        const { email } = decoded;

        // Zaktualizuj użytkownika w bazie danych, aby oznaczyć go jako zweryfikowanego
        const sql = "UPDATE uzytkownicy SET verified = ? WHERE email = ?";
        con.query(sql, [true, email], (err, result) => {
            if (err) {
                console.error("Error updating user verification:", err);
                return res.status(500).send('Wewnętrzny błąd serwera');
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
                <!DOCTYPE html>
                    <html lang="pl">

                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
                        <title>Rejestracja zakończona</title>
                        <link rel="stylesheet" href="styles.css"> <!-- Link do Twojego pliku CSS -->
                    </head>

                    <body>
                        <main>
                            <div id="form-container">
                                <h1>Rejestracja zakończona!</h1>
                                <p>Dziękujemy za zarejestrowanie się. Twój e-mail został pomyślnie zweryfikowany!</p>
                                <p>Za chwilę zostaniesz przeniesiony do strony logowania.</p>
                                <script>
                                    setTimeout(() => {
                                        window.location.href = '/login.ejs';
                                    }, 5000); // Przekierowanie po 3 sekundach
                                </script>
                            </div>
                        </main>
                    </body>

                    </html>
            `);

        });
    });
});









app.get('/login.ejs', checkNotAuth, (req, res) => {
    res.render("login.ejs")

});



app.get('/register.ejs', (req, res) => {
    res.render("register.ejs")
});


app.delete("/logout", (req, res) => {
    req.logOut(req.user, err => {
        if (err) return next(err)
        res.redirect("/indexFirst.html")
    })
})

// Endpoint do odbierania danych z formularza
app.post('/api/data', authenticateToken, (req, res) => {
    const { name, type, color, bgcolor, description, imageSrc, uzytkownik_id, pokedexNumber } = req.body.pokemonData;

    // Walidacja danych wejściowych
    if (!name || !type || !color || !bgcolor || !description || !imageSrc || !uzytkownik_id || !pokedexNumber) {
        return res.status(400).json({ error: 'Wszystkie pola są wymagane.' });
    }

    // Upewnij się, że uzytkownik_id pochodzi z req.user (tokena)
    if (uzytkownik_id !== req.userId) { // Zmiana na req.userId
        return res.status(403).json({ error: 'Nie masz uprawnień do dodawania danych.' });
    }

    const sql = "INSERT INTO pokeinfo1 (name, type, color, bgcolor, description, imageSrc, uzytkownik_id, pokedexNumber) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    con.query(sql, [name, type, color, bgcolor, description, imageSrc, uzytkownik_id, pokedexNumber], (err, result) => {
        if (err) {
            console.error("Błąd podczas wstawiania:", err);
            return res.status(500).json({ error: 'Błąd podczas wstawiania danych' });
        }
        console.log("1 record inserted");
        res.status(200).json({ message: 'Dane zapisane pomyślnie!' });
    });
});




app.post('/api/dataImage', authenticateToken, (req, res) => {
    const { image, uzytkownik_id } = req.body.pokemonImageData;

    // Walidacja danych wejściowych
    if (!image) {
        return res.status(400).json({ error: 'Obraz jest wymagany.' });
    }

    if (uzytkownik_id !== req.userId) { // Zmiana na req.userId
        return res.status(403).json({ error: 'Nie masz uprawnień do dodawania danych.' });
    }

    const sql = "INSERT INTO pokeimage (image, uzytkownik_id) VALUES (?, ?)";
    con.query(sql, [image, uzytkownik_id], (err, result) => {
        if (err) {
            console.error("Błąd podczas wstawiania:", err);
            return res.status(500).json({ error: 'Błąd podczas wstawiania danych' });
        }
        console.log("1 record inserted");
        res.status(200).json({ message: 'Dane zapisane pomyślnie!' });
    });
});

app.get('/api/dataImage1', authenticateToken, (req, res) => {
    const sql = "SELECT image FROM pokeimage ORDER BY id DESC LIMIT 1";  // Get the latest image
    con.query(sql, (err, result) => {
        if (err) {
            console.error("Błąd podczas pobierania danych:", err);
            return res.status(500).json({ error: 'Błąd podczas pobierania danych' });
        }
        if (result.length > 0) {
            const image = result[0].image;
            res.status(200).json({ pokemonImageData: image });
        } else {
            res.status(404).json({ error: 'Brak danych obrazu.' });
        }
    });
});

app.get('/api/pokemon', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'User not logged in' });
    }

    // Zwróć userId zalogowanego użytkownika z sesji
    const userId = req.session.userId;
    const sql = "SELECT pokeinfo1.* FROM pokeinfo1 JOIN uzytkownicy ON pokeinfo1.uzytkownik_id = uzytkownicy.idUser WHERE uzytkownicy.idUser = ?";

    con.query(sql, [userId], (err, results) => {
        if (err) {
            console.error("Błąd podczas pobierania danych:", err);
            return res.status(500).json({ error: 'Błąd podczas pobierania danych' });
        }
        res.status(200).json(results); // Return results as JSON
    });
});

app.get('/api/pokemonNumber/:id', (req, res) => {
    const pokemonId = req.params.id; // Get the ID from the request parameters
    const sql = "SELECT * FROM pokeinfo1 WHERE id = ?"; // Corrected SQL query

    con.query(sql, [pokemonId], (err, results) => {
        if (err) {
            console.error("Błąd podczas pobierania danych:", err);
            return res.status(500).json({ error: 'Błąd podczas pobierania danych' });
        }
        res.status(200).json(results); // Return results as JSON
    });
});

app.post('/api/deleteAndReset', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ message: 'User not logged in' });
    }

    const userId = req.session.userId;
    const { idToDelete } = req.body;

    if (!idToDelete) {
        console.log('No ID provided');
        return res.status(400).send('ID is required');
    }

    const deleteAndReset = (idToDelete) => {
        const deleteQuery = 'DELETE FROM pokeinfo1 WHERE id = ? AND uzytkownik_id = ?';
        con.query(deleteQuery, [idToDelete, userId], (err, results) => {
            if (err) {
                console.error('Error deleting record:', err);
                return res.status(500).send('Error deleting record');
            }
            console.log(`Deleted record with ID ${idToDelete}`);

            // Fetching all records for the specific user after deletion
            const selectAllQuery = 'SELECT id FROM pokeinfo1 WHERE uzytkownik_id = ? ORDER BY id';
            con.query(selectAllQuery, [userId], (err, records) => {
                if (err) {
                    console.error('Error fetching remaining records:', err);
                    return res.status(500).send('Error fetching remaining records');
                }

                // Updating IDs for all remaining records
                const updatePromises = records.map((record, index) => {
                    const newId = index + 1; // Assign new IDs starting from 1
                    const updateQuery = 'UPDATE pokeinfo1 SET id = ? WHERE id = ? AND uzytkownik_id = ?';
                    return new Promise((resolve, reject) => {
                        con.query(updateQuery, [newId, record.id, userId], (err, results) => {
                            if (err) {
                                return reject(err);
                            }
                            resolve();
                        });
                    });
                });

                // After completing all updates
                Promise.all(updatePromises)
                    .then(() => {
                        const resetAutoIncrementQuery = 'ALTER TABLE pokeinfo1 AUTO_INCREMENT = ?';
                        con.query(resetAutoIncrementQuery, [records.length + 1], (err, results) => {
                            if (err) {
                                console.error('Error resetting autoincrement:', err);
                                return res.status(500).send('Error resetting autoincrement');
                            }
                            console.log('ID and autoincrement updated successfully');
                            res.status(200).send({ message: 'Pokémon deleted, IDs updated, and autoincrement reset' });
                        });
                    })
                    .catch(err => {
                        console.error('Error updating IDs:', err);
                        res.status(500).send('Error updating IDs');
                    });
            });
        });
    };

    deleteAndReset(idToDelete);
});








app.get('/photoCard.html', checkAuth, (req, res) => {
    fs.readFile('./photoCard.html', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});




const { GoogleGenerativeAI } = require("@google/generative-ai");


const upload = multer({ dest: "uploads/" }); // Folder for temporary image storage

app.use(express.static('public')); // Serve static files from 'public' folder

const genAI = new GoogleGenerativeAI("AIzaSyB9QG0zEu-VI18iz1tZTOso8RIA94ntEqk");
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Route for main page



app.get('/', checkAuth, (req, res) => {
    fs.readFile('./indexFirst.html', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});

app.get('/indexFirst.html', (req, res) => {
    fs.readFile('./indexFirst.html', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});

// Other routes
app.get('/indexMain.ejs', checkAuth, (req, res) => {
    fs.readFile('./indexMain.ejs', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});


app.get('/PoetsenOne-Regular.ttf', (req, res) => {
    res.sendFile(path.join(__dirname, 'fonts', 'PoetsenOne-Regular.ttf'));
});







app.get('/indexCamera.html', checkAuth, (req, res) => {

    fs.readFile('./indexCamera.html', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});


app.get('/photo.html', checkAuth, (req, res) => {
    fs.readFile('./photo.html', 'utf8', (err, html) => {
        if (err) {
            res.status(500).send('Sorry, out of order');
        } else {
            res.send(html);
        }
    });
});

// Endpoint to analyze image and generate AI response
app.post('/analyze', authenticateToken, upload.single('photo'), async (req, res) => {
    const photoPath = req.file.path; // Ścieżka do przesłanego zdjęcia
    const promptPath = path.join(__dirname, 'prompt.txt');

    try {
        const prompt = await fs.promises.readFile(promptPath, 'utf8');

        const image = {
            inlineData: {
                data: Buffer.from(fs.readFileSync(photoPath)).toString("base64"),
                mimeType: "image/png",
            },
        };

        const result = await model.generateContent([prompt, image]);

        const responseText = await result.response.text();
        const [id, name, type, color, bgcolor, pokedexNumber, ...descriptionParts] = responseText.split('\n');
        const description = descriptionParts.join(' ').trim();

        res.json({
            pokemonId: id || "N/A",
            pokemonName: name || "Unknown",
            pokemonType: type || "Unknown",
            pokemonColor: color || "Unknown",
            pokemonBgColor: bgcolor || "Unknown",
            description: description || "Brak opisu.",
            pokedexNumber: pokedexNumber || "brak danych"
        });
    } catch (error) {
        res.status(500).json({ error: "An error occurred while processing the image." });
    } finally {
        fs.unlinkSync(photoPath);
    }
});


function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.redirect("/indexFirst.html");
    }

    // Opcjonalnie: Możesz dodać logikę do weryfikacji tokenu tutaj

    res.redirect("/indexFirst.html"); // Jeśli nie jest uwierzytelniony i nie ma tokenu
}

function checkNotAuth(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/indexMain.ejs")
    }
    const token = req.headers['authorization']?.split(' ')[1];
    if (token) {
        return res.redirect("/indexMain.ejs"); // Jeśli token istnieje, przekieruj do indexMain.html
    }
    next()
}
// Start server
app.listen(3000, () => {
    console.log('App available on http://localhost:3000/indexFirst.html');
});
