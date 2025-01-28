import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3061;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files from 'public' directory

const JWT_SECRET = process.env.JWT_SECRET || 'votre_secret';
const BLOCK_DURATION = 10 * 60 * 1000; // 10 minutes

const loginAttempts = {};
let users = [];

// Function to hash passwords
async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

// Load users with hashed passwords
const loadUsers = async () => {
  try {
    const rawUsers = [
      { id: 1, nom: "Dupont", prenom: "Jean", username: "jdupont", password: "password123", role: "Admin", site: "Cofat Tunis", email: "jdupont@yahoo.com" },
      { id: 2, nom: "Martin", prenom: "Claire", username: "cmartin", password: "password456", role: "User", site: "Cofat Mateur", email: "cmartin@yahoo.com" },
      { id: 3, nom: "Durand", prenom: "Pierre", username: "pdurand", password: "password789", role: "Manager", site: "Cofat Kairouan", email: "pdurand@yahoo.com" },
    ];

    users = await Promise.all(rawUsers.map(async (user) => ({
      ...user,
      password: await hashPassword(user.password)
    })));

    console.log("Users loaded with hashed passwords.");
  } catch (error) {
    console.error("Error loading users:", error);
  }
};

// Function to generate an .eml file (email format)
const generateEML = async (from, to, subject, text) => {
  const emlContent = `
From: ${from}
To: ${to}
Subject: ${subject}

${text}
`;

  const filePath = path.join(__dirname, `email_${Date.now()}.eml`);
  try {
    await fs.writeFile(filePath, emlContent);
    console.log(`EML file generated successfully: ${filePath}`);
    return filePath;
  } catch (err) {
    console.error('Error generating .eml file', err);
    return null;
  }
};

// Function to get public IP address
const getPublicIP = async () => {
  try {
    const response = await axios.get('https://api.ipify.org?format=json');
    return response.data.ip;
  } catch (error) {
    console.error("Error retrieving public IP", error);
    return null;
  }
};

// Function to get geolocation via IP address
const getGeolocation = async (ip) => {
  if (ip.startsWith('::ffff:') || ip === '127.0.0.1' || ip === '::1') {
    ip = await getPublicIP();
  }

  if (!ip) {
    return "Location unavailable";
  }

  try {
    const response = await axios.get(`http://ipinfo.io/${ip}/json`);
    const { city, region, country, loc } = response.data;
    return `Location: ${city || 'Unknown'}, ${region || 'Unknown'}, ${country || 'Unknown'} (Coordinates: ${loc || 'Unknown'})`;
  } catch (error) {
    console.error("Error during geolocation", error);
    return "Location unavailable";
  }
};

// Function to send an email after 4 failed attempts
const sendAlertEmail = async (user, ip) => {
  const from = '"Cofat Support" <noreply@cofat.com>';
  const to = 'mahdichaabani33@gmail.com'; // Alert receiving address
  const subject = `Failed login attempt for ${user.username}`;
  
  const locationInfo = await getGeolocation(ip);
  const text = `There was a failed login attempt for user ${user.prenom} ${user.nom}.
  ${locationInfo}`;

  const emlFilePath = await generateEML(from, to, subject, text);
  if (emlFilePath) {
    console.log(`Alert email saved in file: ${emlFilePath}`);
  }
};

// Serve the login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Authentication route
app.post('/API/Authentification', async (req, res) => {
  const { username, password: reqPassword } = req.body;
  const userIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  console.log("Captured IP address:", userIP);
  
  const user = users.find(user => user.username === username);

  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  if (!reqPassword || !user.password) {
    return res.status(400).json({ message: 'Password fields are missing.' });
  }

  try {
    const passwordMatch = await bcrypt.compare(reqPassword, user.password);

    if (!passwordMatch) {
      loginAttempts[username] = loginAttempts[username] || { attempts: 0, isBlocked: false, blockTime: null };
      loginAttempts[username].attempts++;

      if (loginAttempts[username].attempts >= 4) {
        loginAttempts[username].isBlocked = true;
        loginAttempts[username].blockTime = Date.now();
        await sendAlertEmail(user, userIP);
        return res.status(403).json({ message: 'Account blocked after multiple failed attempts.' });
      }

      return res.status(401).json({ message: `Incorrect password. Attempt ${loginAttempts[username].attempts} of 4.` });
    }

    // Reset attempts if password is correct
    loginAttempts[username] = { attempts: 0, isBlocked: false, blockTime: null };
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });

  } catch (error) {
    console.error("Error comparing passwords:", error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// Wait for users to be loaded before starting the server
loadUsers().then(() => {
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
});

// For demonstration purposes, let's log the users array
console.log("Users:", users);