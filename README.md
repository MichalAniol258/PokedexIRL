
# Pokedex in Real Life

**Pokedex in Real Life** is an AI-powered project that brings the world of Pokémon to life. It allows users to capture images of real-world objects, analyze them through AI, and provide detailed information about the Pokémon they resemble. Whether you're looking for a fun and interactive way to learn about Pokémon or want to explore how AI can be applied to image recognition, this project offers a creative fusion of technology and entertainment.

## Features

- 🧠 **AI-Powered Pokémon Recognition**: Use AI to analyze real-world images and identify the Pokémon they resemble.
- 📸 **Webcam Integration**: Capture images directly from your webcam and analyze them in real-time.
- 📊 **Detailed Pokémon Information**: Retrieve comprehensive details about recognized Pokémon, including type, stats, and evolution.
- 🔐 **User Authentication**: Secure login and registration system powered by Passport.js and JWT-based email verification.
- 💾 **MySQL Integration**: Store user data and Pokémon analyses in a structured database.
- 🔍 **Design**: The app is specifically designed for mobile devices, offering an intuitive interface and full responsiveness on phones.
- 🖼️ **Graphics**: All images used in the project are sourced from the internet.
  
## How It Works

1. **Image Capture**: Users capture images from their webcam or upload images.
2. **AI Analysis**: The AI model processes the image and identifies the Pokémon based on various characteristics like color and shape.
3. **Pokémon Data**: After recognition, detailed information about the Pokémon is displayed, including type, stats, evolutions, and more.
4. **User Data**: Results are saved to the user's profile for future reference and comparison.

## Technologies Used

- **Frontend**:
  - HTML5, CSS3, JavaScript (ES6+)
  - Responsive Design (Flexbox, Media Queries)
  - Webcam API
- **Backend**:
  - Node.js, Express.js
  - Passport.js for authentication
  - JWT for email verification and secure authentication
  - MySQL for data storage
- **AI Integration**:
  - Custom AI model for Pokémon identification
  - Image analysis and recognition logic
- **Database**:
  - MySQL for storing user and Pokémon data
- **Testing**:
  - Thunder Client for API testing

## Getting Started

### Prerequisites

- **Node.js**: Make sure you have [Node.js](https://nodejs.org/) installed.
- **MySQL**: Set up a MySQL database for user data and Pokémon information.

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/MichalAniol258/PokedexIRL.git
   cd PokedexIRL
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Set up the MySQL database. Create the following tables:
   - `uzytkownicy`: Stores user details.
   - `pokeinfo1`: Stores Pokémon analysis information.

4. Configure the `.env` file with your database credentials and JWT secret:
   ```bash
   DB_HOST=localhost
   DB_USER=root
   DB_PASS=password
   DB_NAME=pokedex
   JWT_SECRET=your_jwt_secret
   ```

5. Run the server:
   ```bash
   npm run s
   ```

6. Open your browser and go to `http://localhost:3000`.


## Usage

- **User Registration**: Sign up and log in using the registration form.
- **Image Capture**: Use the webcam to capture images or upload photos.
- **Pokémon Analysis**: Let the AI identify the Pokémon, and view detailed information.
- **View History**: Check previous analyses and results from your user profile.
