// passportConfig.js
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const con = require('./dbConnection'); // Zakładam, że masz plik z konfiguracją połączenia do bazy

module.exports = function (passport) {
    // Definiowanie strategii lokalnej
    passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
        const sql = "SELECT * FROM uzytkownicy WHERE email = ?";
        con.query(sql, [email], async (err, results) => {
            if (err) {
                return done(err);
            }
            if (results.length === 0) {
                return done(null, false, { message: 'No user with that email' });
            }

            const user = results[0];

            try {
                const match = await bcrypt.compare(password, user.password);
                if (match) {
                    return done(null, user); // Logowanie zakończone sukcesem
                } else {
                    return done(null, false, { message: 'Password incorrect' });
                }
            } catch (err) {
                return done(err);
            }
        });
    }));

    // Serializacja użytkownika do sesji
    passport.serializeUser((user, done) => {
        done(null, user.idUser);
    });

    // Deserializacja użytkownika z sesji
    passport.deserializeUser((id, done) => {
        const sql = "SELECT * FROM uzytkownicy WHERE idUser = ?";
        con.query(sql, [id], (err, results) => {
            if (err) {
                return done(err);
            }
            return done(null, results[0]);
        });
    });
};
