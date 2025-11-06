if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}
// Core dependencies
const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');
const methodOverride = require('method-override');
const twilio = require('twilio');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fsPromises = require('fs').promises;
// Optional email support via nodemailer if available and configured
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (e) {
  nodemailer = null;
}
// OpenAI SDK
const { Configuration, OpenAIApi } = require('openai');
let client = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  try {
    client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  } catch (err) {
    console.warn('Twilio initialization failed:', err && err.message ? err.message : err);
    client = null;
  }
} else {
  console.warn('Twilio not configured (TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN missing). SOS feature disabled.');
}

// Configure OpenAI client if key is present
let openai = null;
if (process.env.OPENAI) {
  const configuration = new Configuration({ apiKey: process.env.OPENAI });
  openai = new OpenAIApi(configuration);
}


// MongoDB Atlas connection (optional)
if (process.env.MONGODB_URI) {
  mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }).then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));
} else {
  console.warn('MONGODB_URI not set — running without database connection. Some features will be disabled.');
}

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  phone: String,
  password: String,
  age: String,
  userType: { type: String, enum: ['patient', 'caretaker'] },
  emergencyContact: {
    name: String,
    email: String,
    phone: String,
  },
  journal: [{
    content: String,
    mood: String,
    timestamp: { type: Date, default: Date.now }
  }],
  connections: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  connectionRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  awards: [String],
  games: { memoryCards: [{ mode: String, moves: Number, time: Number, timestamp: { type: Date, default: Date.now } }], sudoku: [{ time: Number, difficulty: String, timestamp: { type: Date, default: Date.now } }], minimi: [{ score: Number, time: Number }] },
  // scores: [{
  //   score: Number,
  //   gameType: String,
  //   difficulty: String,
  //   timePerrun: Number,
  //   movesPerrun: Number,
  //   rangeOfMovement: [Number],
  //   timestamp: { type: Date, default: Date.now }
  // }],
  // Doctor-specific fields
  qualification: String,
  nmcRegistrationNo: String,
  yearOfRegistration: Number,
  medicalCouncil: String
});


const User = mongoose.model('User', userSchema);
const upcomingEventSchema = new mongoose.Schema({
  event: String,
  date: String,
  date_end: String
});
const UpcomingEvent = mongoose.model('upcoming', upcomingEventSchema);



const forumSchema = new mongoose.Schema({
  heading: {
    type: String,
    required: true
  },
  description: String,
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  tags: [String],
  comments: [{
    content: String,
    author: String,
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  likes: {
    type: Number,
    default: 0
  }

});

const Forum = mongoose.model('Forum', forumSchema);




// Passport initialization
const initializePassport = require('./passport-config');

// Decide whether to use MongoDB-backed users or a file-based dev user store
let devStore = null;
if (!process.env.MONGODB_URI) {
  devStore = require('./dev-user-store');
}

// Helper to list all users (devStore or DB)
async function readAllUsers() {
  if (devStore) {
    // devStore doesn't expose a readAll function; read the file directly
    const fs = require('fs').promises;
    const p = path.join(__dirname, 'data', 'users.json');
    try {
      const txt = await fs.readFile(p, 'utf8');
      return JSON.parse(txt || '[]');
    } catch (e) {
      return [];
    }
  }
  return await User.find({}).lean();
}

initializePassport(passport, async (email) => {
  try {
    if (devStore) {
      return await devStore.findByEmail(email);
    }
    const user = await User.findOne({ email: email });
    return user;
  } catch (err) {
    console.error("Error fetching user by email:", err);
    return null;
  }
}, async (id) => {
  if (devStore) return await devStore.findById(id);
  return await User.findById(id);
});

app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Simple request logger for debugging (prints method and path)
app.use((req, res, next) => {
  try {
    console.log('REQ>', req.method, req.path); // lightweight logging
  } catch (e) {}
  next();
});

app.use(flash());
// Ensure a session secret is always provided. Use a fallback in development but warn.
const sessionSecret = process.env.SESSION_SECRET || 'dev-secret-change-this-for-production';
if (!process.env.SESSION_SECRET) {
  console.warn('SESSION_SECRET not set. Using a development fallback secret. Set SESSION_SECRET in .env for production.');
}
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days in milliseconds
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));

// Make authenticated user available in all EJS templates as `user` to avoid undefined references
app.use((req, res, next) => {
  try {
    res.locals.user = req.user || null;
  } catch (e) {
    res.locals.user = null;
  }
  next();
});

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'public', 'uploads');
fsPromises.mkdir(uploadsDir, { recursive: true }).catch(() => {});

// Multer setup for uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const name = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,8) + ext;
    cb(null, name);
  }
});
const upload = multer({ storage });

// Define an async function to fetch upcoming events
async function fetchAndProcessUpcomingEvents() {
  try {
    const upcomingEvents = await UpcomingEvent.find({}).lean();
    // console.log("Upcoming Events:", upcomingEvents); // Log retrieved events

    // Convert date strings to Date objects
    upcomingEvents.forEach(event => {
      event.date = new Date(event.date);
      if (event.date_end) {
        event.date_end = new Date(event.date_end);
      }
    });

    // Get the current date
    const currentDate = new Date();

    // Filter out past events
    const upcomingEventsFiltered = upcomingEvents.filter(event => event.date >= currentDate);

    // Sort upcoming events by date in ascending order
    upcomingEventsFiltered.sort((a, b) => a.date - b.date);

    // Take the latest 3 upcoming events
    const latestUpcomingEvents = upcomingEventsFiltered.slice(0, 3);

    // console.log("Latest 3 upcoming events compared to current date:");
    console.log(latestUpcomingEvents);

    return latestUpcomingEvents;
  } catch (error) {
    console.error('Error fetching and processing upcoming events:', error);
    return []; // Return an empty array if there's an error
  }
}

// Dev-store helper to add event
async function addUpcomingEventForPatient(patientId, eventObj) {
  if (devStore) {
    const p = await devStore.findById(patientId);
    if (!p) return false;
    p.events = p.events || [];
    p.events.push(eventObj);
    await devStore.updateUser(patientId, { events: p.events });
    return true;
  } else {
    const patient = await User.findById(patientId);
    if (!patient) return false;
    patient.events = patient.events || [];
    patient.events.push(eventObj);
    await patient.save();
    return true;
  }
}


// Home page
app.get('/', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    if (user.userType === 'patient') {
      const latestUpcomingEvents = await fetchAndProcessUpcomingEvents();
      // console.log(latestUpcomingEvents);
      // Pass a flag indicating whether OpenAI is available; do not expose the API key
      res.render('index.ejs', { user: user, upcomingEvents: latestUpcomingEvents, openaiEnabled: !!process.env.OPENAI });
    } else {
        // Non-patient users are caretakers in this app
        res.redirect('/caretaker-home');
    }
  } catch (error) {
    console.error('Error fetching upcoming events:', error);
    res.status(500).send('Error fetching upcoming events');
  }
});


// Login page
app.get('/login', checkNotAuthenticated, (req, res) => {
  // Pass flash messages to view to avoid undefined variable in template
  const errorMsg = req.flash('error');
  const role = req.query.role || null;
  res.render('login.ejs', { messages: { error: errorMsg && errorMsg.length ? errorMsg[0] : null }, role });
});

app.post('/login', checkNotAuthenticated, (req, res, next) => {
  passport.authenticate('local', async (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      req.flash('error', info && info.message ? info.message : 'Login failed');
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      // redirect based on role
      try {
        const u = user;
        const requestedRole = req.body.role;
        // If a role was requested, ensure the authenticated user matches it
        if (requestedRole && u.userType !== requestedRole) {
          req.flash('error', 'Account role does not match selected login role');
          req.logout(() => {});
          return res.redirect('/login');
        }
        if (u.userType === 'caretaker') return res.redirect('/caretaker-home');
        return res.redirect('/');
      } catch (e) {
        return res.redirect('/');
      }
    });
  })(req, res, next);
});


const medicalCouncils = [
  "Andhra Pradesh Medical Council",
  "Arunachal Pradesh Medical Council",
  "Assam Medical Council",
  "Bihar Medical Council",
  "Chandigarh Medical Council",
  "Chhattisgarh Medical Council",
  "Delhi Medical Council",
  "Goa Medical Council",
  "Gujarat Medical Council",
  "Haryana Medical Council",
  "Himachal Pradesh Medical Council",
  "Jammu and Kashmir Medical Council",
  "Jharkhand Medical Council",
  "Karnataka Medical Council",
  "Kerala Medical Council",
  "Madhya Pradesh Medical Council",
  "Maharashtra Medical Council",
  "Manipur Medical Council",
  "Meghalaya Medical Council",
  "Mizoram Medical Council",
  "Nagaland Medical Council",
  "Odisha State Medical Council",
  "Puducherry Medical Council",
  "Punjab Medical Council",
  "Rajasthan Medical Council",
  "Sikkim Medical Council",
  "Tamil Nadu Medical Council",
  "Telangana State Medical Council",
  "Tripura Medical Council",
  "Uttar Pradesh Medical Council",
  "Uttarakhand Medical Council",
  "West Bengal Medical Council"
];

// Register page
app.get('/register', checkNotAuthenticated, (req, res) => {
  try {
    // Some code here
    const userrr = req.flash('user');
    const messages = {
      error: (req.flash('error') && req.flash('error').length) ? req.flash('error')[0] : null,
      success: (req.flash('success') && req.flash('success').length) ? req.flash('success')[0] : null
    };
    res.render('register.ejs', { userrr, medicalCouncils, messages });

  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    // If using devStore (no MongoDB), delegate to file-based store
    if (devStore) {
      const existingUser = await devStore.findByEmail(req.body.email);
      if (existingUser) {
        req.flash('user', existingUser);
        return res.redirect('/register');
      }

      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const created = await devStore.createUser({
        username: req.body.name,
        email: req.body.email,
        phone: req.body.userPhone,
        password: hashedPassword,
        age: req.body.age,
        userType: req.body.userType,
        emergencyContact: {
          name: req.body.emergencyName,
          email: req.body.emergencyEmail,
          phone: req.body.emergencyPhone,
        },
        qualification: req.body.qualification,
        nmcRegistrationNo: req.body.nmcRegistrationNo,
        yearOfRegistration: req.body.yearOfRegistration,
        medicalCouncil: req.body.medicalCouncil
      });

      // Log them in by calling req.login with the created user shape
      req.login(created, (err) => {
        if (err) {
          console.error('Error during login after registration:', err);
          return res.redirect('/login');
        }
        req.flash('success', 'Registration successful. You have been logged in.');
        return res.redirect('/');
      });
      return;
    }

    // Default behavior: MongoDB-backed registration
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      req.flash('user', existingUser);
      return res.redirect('/register');
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.name,
      email: req.body.email,
      phone: req.body.userPhone,
      password: hashedPassword,
      age: req.body.age,
      userType: req.body.userType,
      emergencyContact: {
        name: req.body.emergencyName,
        email: req.body.emergencyEmail,
        phone: req.body.emergencyPhone,
      },
      qualification: req.body.qualification,
      nmcRegistrationNo: req.body.nmcRegistrationNo,
      yearOfRegistration: req.body.yearOfRegistration,
      medicalCouncil: req.body.medicalCouncil
    });
    await user.save();
    req.login(user, (err) => {
      if (err) {
        console.error('Error during login after registration:', err);
        return res.redirect('/login');
      }
      req.flash('success', 'Registration successful. You have been logged in.');
      return res.redirect('/');
    });

  } catch (error) {
    console.error('Error during registration:', error);
    return res.redirect('/register');
  }
});



// Logout route
app.delete('/logout', (req, res) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/login');
  });
});


// Server-side chat endpoint — forwards chat to OpenAI using model gpt-5-mini
app.post('/api/chat', checkAuthenticated, async (req, res) => {
  try {
    if (!openai) {
      return res.json({ error: 'AI not configured on server.' });
    }

    const { message, username } = req.body;
    if (!message) return res.status(400).json({ error: 'Message is required' });

    // Build a gentle system prompt for role and persona
    const systemPrompt = `You are a compassionate medical assistant for an elderly user named ${username}. Keep responses short, friendly, and supportive.`;

    const response = await openai.createChatCompletion({
      model: 'gpt-5-mini',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: message }
      ],
      max_tokens: 300,
      temperature: 0.6,
    });

    const reply = response.data?.choices?.[0]?.message?.content?.trim() || 'No reply';
    res.json({ reply });
  } catch (error) {
    console.error('Error /api/chat:', error?.response?.data || error.message || error);
    res.status(500).json({ error: 'Failed to get response from AI' });
  }
});

app.post('/memoryCard-game-over', checkAuthenticated, async (req, res) => {
  try {
    const currentUser = await req.user;
    console.log("Received game over data:", req.body);
    const { mode, moves, time } = req.body; // Extract data from the request body
    console.log(req.body);
    // Assuming currentUser has a 'games.memoryCards' array field
    currentUser.games.memoryCards.push({
      mode,
      moves,
      time
    });

    // Save the updated user document
    await currentUser.save();
    res.status(200).json({ success: true, message: 'Score updated successfully' });
  } catch (error) {
    console.error('Error updating score:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


app.post('/sudoku-game-over', checkAuthenticated, async (req, res) => {
  try {
    const currentUser = await req.user;
    console.log("Received game over data:", req.body);
    const time = req.body.timer; // Extract data from the request body
    console.log(req.body);
    // Assuming currentUser has a 'games.memoryCards' array field
    currentUser.games.sudoku.push({ time, difficulty: "none" });

    // Save the updated user document
    await currentUser.save();

    res.status(200).json({ success: true, message: 'Score updated successfully' });
  } catch (error) {
    console.error('Error updating score:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});

app.get('/doctor-home', checkAuthenticated, async (req, res) => {
  try {
    const doctor = await req.user;

    // Fetch all patient details in connectionRequests
    const connectionRequests = await Promise.all(
      doctor.connectionRequests.map(async (request) => {
        const patient = await User.findById(request._id);
        return { patient }; // Include _id for later use in the template
      })
    );

    const connections = await Promise.all(
      doctor.connections.map(async (request) => {
        const patient = await User.findById(request._id);
        return { patient }; // Include _id for later use in the template
      })
    );

     res.render('doctor-home.ejs', { user: doctor, connectionRequests, connections, roleLabel: 'Doctor' });
  } catch (error) {
    console.error('Error fetching doctor:', error);
  res.render('doctor-home.ejs', { error: 'Internal Server Error', user: req.user || null, connectionRequests: [], connections: [], roleLabel: 'Doctor' });
  }
});

// New caretaker-specific route (same view for now)
app.get('/caretaker-home', checkAuthenticated, async (req, res) => {
  try {
    const caretaker = await req.user;

    const connectionRequests = await Promise.all(
      (caretaker.connectionRequests || []).map(async (requestId) => {
        // requestId may be a string id or an object in Mongo; handle both
        const id = (requestId && requestId._id) ? requestId._id : requestId;
        if (devStore) {
          const p = await devStore.findById(id);
          return { patient: p };
        }
        const patient = await User.findById(id);
        return { patient };
      })
    );

    const connections = await Promise.all(
      (caretaker.connections || []).map(async (connId) => {
        const id = (connId && connId._id) ? connId._id : connId;
        if (devStore) {
          const p = await devStore.findById(id);
          return { patient: p };
        }
        const patient = await User.findById(id);
        return { patient };
      })
    );

    res.render('doctor-home.ejs', { user: caretaker, connectionRequests, connections, roleLabel: 'Caretaker' });
  } catch (error) {
    console.error('Error fetching caretaker:', error);
  res.render('doctor-home.ejs', { error: 'Internal Server Error', user: req.user || null, connectionRequests: [], connections: [], roleLabel: 'Caretaker' });
  }
});




app.get('/journal', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    res.render('journal.ejs', { user: user });
  } catch (error) {
    console.error('Error fetching user for journal:', error);
    // Handle the error appropriately, for example, redirecting to an error page
    res.status(500).send('Internal Server Error');
  }
});

// Development debug page: lists devStore users (only when devStore active)
app.get('/dev-requests', checkAuthenticated, async (req, res) => {
  if (!devStore) return res.status(404).send('Not available');
  const fs = require('fs').promises;
  const p = path.join(__dirname, 'data', 'users.json');
  try {
    const txt = await fs.readFile(p, 'utf8');
    const users = JSON.parse(txt || '[]');
    res.render('dev-requests.ejs', { users });
  } catch (e) {
    res.status(500).send('Error reading dev store');
  }
});

// Dev-only: set password for a devStore user
app.post('/dev-set-password', checkAuthenticated, async (req, res) => {
  if (!devStore) return res.status(404).send('Not available');
  try {
    const { userId, password } = req.body;
    if (!userId || !password) return res.redirect('/dev-requests');
    const hashed = await bcrypt.hash(password, 10);
    await devStore.updateUser(userId, { password: hashed });
    req.flash('success', 'Password updated for user.');
    res.redirect('/dev-requests');
  } catch (e) {
    console.error('Error setting dev password:', e);
    res.status(500).send('Error');
  }
});

// Developer page
app.get('/developer', (req, res) => {
  res.render('developer.ejs');
});

// Caretaker schedule & assign page
app.get('/caretaker-schedule', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    if (user.userType !== 'caretaker') return res.status(403).send('Forbidden');
    // List patients (connections)
    let patients = [];
    if (devStore) {
      const me = await devStore.findById(user.id || user._id);
      const connIds = me.connections || [];
      for (const cid of connIds) {
        const p = await devStore.findById(cid);
        if (p) patients.push(p);
      }
    } else {
      for (const c of user.connections || []) {
        const p = await User.findById(c);
        if (p) patients.push(p);
      }
    }
    res.render('caretaker-schedule.ejs', { user, patients, messages: { success: req.flash('success'), error: req.flash('error') } });
  } catch (e) {
    console.error('Error loading caretaker schedule:', e);
    res.status(500).send('Error');
  }
});

// Assign medication to a patient
app.post('/caretaker/assign-med', checkAuthenticated, async (req, res) => {
  try {
    const caretaker = await req.user;
    if (caretaker.userType !== 'caretaker') return res.status(403).send('Forbidden');
    const { patientId, medName, dose, time } = req.body;
    if (!patientId || !medName || !time) {
      req.flash('error', 'Missing required fields');
      return res.redirect('/caretaker-schedule');
    }
    const medEntry = { id: Date.now().toString(36), medName, dose: dose || '', time, assignedBy: caretaker.id || caretaker._id, read: false };
    if (devStore) {
      const patient = await devStore.findById(patientId);
      if (!patient) {
        req.flash('error', 'Patient not found');
        return res.redirect('/caretaker-schedule');
      }
      patient.medications = patient.medications || [];
      patient.medications.push(medEntry);
      await devStore.updateUser(patientId, { medications: patient.medications });
    } else {
      const patient = await User.findById(patientId);
      if (!patient) {
        req.flash('error', 'Patient not found');
        return res.redirect('/caretaker-schedule');
      }
      patient.medications = patient.medications || [];
      patient.medications.push(medEntry);
      await patient.save();
    }
    req.flash('success', 'Medication assigned');
    res.redirect('/caretaker-schedule');
  } catch (e) {
    console.error('Error assigning medication:', e);
    req.flash('error', 'Failed to assign medication');
    res.redirect('/caretaker-schedule');
  }
});

// Assign a song to a patient (can be URL or uploaded file)
app.post('/caretaker/assign-song', checkAuthenticated, upload.single('songFile'), async (req, res) => {
  try {
    const caretaker = await req.user;
    if (caretaker.userType !== 'caretaker') return res.status(403).send('Forbidden');
    const { patientId, title, url } = req.body;
    if (!patientId) {
      req.flash('error', 'Select a patient');
      return res.redirect('/caretaker-schedule');
    }
    let songUrl = url;
    let songTitle = title;
    if (req.file) {
      songUrl = '/uploads/' + req.file.filename;
      songTitle = songTitle || req.file.originalname;
    }
    if (!songUrl) {
      req.flash('error', 'Provide a URL or upload a file');
      return res.redirect('/caretaker-schedule');
    }
    const songEntry = { id: Date.now().toString(36), title: songTitle || 'Untitled', url: songUrl, assignedBy: caretaker.id || caretaker._id };
    if (devStore) {
      const patient = await devStore.findById(patientId);
      if (!patient) {
        req.flash('error', 'Patient not found');
        return res.redirect('/caretaker-schedule');
      }
      patient.assignedSongs = patient.assignedSongs || [];
      patient.assignedSongs.push(songEntry);
      await devStore.updateUser(patientId, { assignedSongs: patient.assignedSongs });
    } else {
      const patient = await User.findById(patientId);
      if (!patient) {
        req.flash('error', 'Patient not found');
        return res.redirect('/caretaker-schedule');
      }
      patient.assignedSongs = patient.assignedSongs || [];
      patient.assignedSongs.push(songEntry);
      await patient.save();
    }
    req.flash('success', 'Song assigned to patient');
    res.redirect('/caretaker-schedule');
  } catch (e) {
    console.error('Error assigning song:', e);
    req.flash('error', 'Failed to assign song');
    res.redirect('/caretaker-schedule');
  }
});

// Caretaker can create calendar events for patients
app.post('/caretaker/create-event', checkAuthenticated, async (req, res) => {
  try {
    const caretaker = await req.user;
    if (caretaker.userType !== 'caretaker') return res.status(403).send('Forbidden');
    const { patientId, event, date, date_end } = req.body;
    if (!patientId || !event || !date) {
      req.flash('error', 'Missing required fields');
      return res.redirect('/caretaker-schedule');
    }
    const eventObj = { id: Date.now().toString(36), event, date, date_end: date_end || null };
    const ok = await addUpcomingEventForPatient(patientId, eventObj);
    if (!ok) {
      req.flash('error', 'Failed to add event');
      return res.redirect('/caretaker-schedule');
    }
    req.flash('success', 'Event added');
    res.redirect('/caretaker-schedule');
  } catch (e) {
    console.error('Error creating event:', e);
    req.flash('error', 'Failed to add event');
    res.redirect('/caretaker-schedule');
  }
});

// Endpoint for patient to fetch notifications (medications)
app.get('/api/notifications', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    const meds = user.medications || [];
    // Return only unread or upcoming meds; client can filter
    res.json({ medications: meds, assignedSongs: user.assignedSongs || [] });
  } catch (e) {
    console.error('Error fetching notifications:', e);
    res.status(500).json({ error: 'Failed to get notifications' });
  }
});

// Favorites - caretakers can add favorite song URLs which are stored on their profile
app.get('/favorites', checkAuthenticated, async (req, res) => {
  const user = await req.user;
  // only caretakers should add favorites; show a form for caretakers
  if (user.userType === 'caretaker') {
    return res.render('add-favorites.ejs', { user });
  }
  // patients can view/play favorites from their connected caretakers
  res.redirect('/play-favorites');
});

app.post('/favorites/add', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    if (user.userType !== 'caretaker') {
      req.flash('error', 'Only caretakers can add favorites');
      return res.redirect('/');
    }
    const { title, url } = req.body;
    const fav = { id: Date.now().toString(36), title, url };
    if (devStore) {
      const existing = await devStore.findById(user.id || user._id);
      const favorites = (existing.favorites || []).concat(fav);
      await devStore.updateUser(user.id || user._id, { favorites });
    } else {
      user.favorites = user.favorites || [];
      user.favorites.push(fav);
      await user.save();
    }
    req.flash('success', 'Favorite added');
    res.redirect('/favorites');
  } catch (err) {
    console.error('Error adding favorite:', err);
    req.flash('error', 'Failed to add favorite');
    res.redirect('/favorites');
  }
});

// Upload a file as a favorite (caretaker only)
app.post('/favorites/upload', checkAuthenticated, upload.single('file'), async (req, res) => {
  try {
    const user = await req.user;
    if (user.userType !== 'caretaker') {
      req.flash('error', 'Only caretakers can upload favorites');
      return res.redirect('/');
    }
    if (!req.file) {
      req.flash('error', 'No file uploaded');
      return res.redirect('/favorites');
    }
    const fileUrl = '/uploads/' + req.file.filename;
    const fav = { id: Date.now().toString(36), title: req.body.title || req.file.originalname, url: fileUrl };

    if (devStore) {
      const existing = await devStore.findById(user.id || user._id);
      const favorites = (existing.favorites || []).concat(fav);
      await devStore.updateUser(user.id || user._id, { favorites });
    } else {
      user.favorites = user.favorites || [];
      user.favorites.push(fav);
      await user.save();
    }
    req.flash('success', 'Favorite uploaded');
    res.redirect('/favorites');
  } catch (err) {
    console.error('Error uploading favorite:', err);
    req.flash('error', 'Failed to upload favorite');
    res.redirect('/favorites');
  }
});

// For patients: play favorites from connected caretakers
app.get('/play-favorites', checkAuthenticated, async (req, res) => {
  const user = await req.user;
  let favorites = [];
  // For devStore, read connections and aggregate
  if (devStore) {
    const me = await devStore.findById(user.id || user._id);
    const conns = me.connections || [];
    for (const cid of conns) {
      const caretaker = await devStore.findById(cid);
      if (caretaker && Array.isArray(caretaker.favorites)) favorites = favorites.concat(caretaker.favorites);
    }
  } else {
    // For MongoDB-backed users, populate connections
    const conns = user.connections || [];
    for (const c of conns) {
      const caretaker = await User.findById(c);
      if (caretaker && Array.isArray(caretaker.favorites)) favorites = favorites.concat(caretaker.favorites);
    }
  }
  res.render('view-memories.ejs', { user, favorites });
});

// Placeholder routes for new navigation items
app.get('/add-memory', checkAuthenticated, async (req, res) => {
  const user = await req.user;
  res.render('add-memory.ejs', { user });
});

app.get('/view-memories', checkAuthenticated, async (req, res) => {
  const user = await req.user;
  res.render('view-memories.ejs', { user });
});

app.get('/reminders', checkAuthenticated, async (req, res) => {
  const user = await req.user;
  res.render('reminders.ejs', { user });
});

// Persist a new memory
app.post('/add-memory', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    const { title, notes } = req.body;
    const entry = { id: Date.now().toString(36), title: title || 'Untitled', notes: notes || '', timestamp: new Date() };

    if (devStore) {
      const existing = await devStore.findById(user.id || user._id);
      const updatedMemories = (existing.memories || []).concat(entry);
      await devStore.updateUser(user.id || user._id, { memories: updatedMemories });
    } else {
      user.memories = user.memories || [];
      user.memories.push(entry);
      await user.save();
    }

    req.flash('success', 'Memory added');
    res.redirect('/view-memories');
  } catch (err) {
    console.error('Error adding memory:', err);
    req.flash('error', 'Failed to add memory');
    res.redirect('/add-memory');
  }
});

// Remove a memory
app.post('/delete-memory', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    const { id } = req.body;
    if (devStore) {
      const existing = await devStore.findById(user.id || user._id);
      const updated = (existing.memories || []).filter(m => m.id !== id);
      await devStore.updateUser(user.id || user._id, { memories: updated });
    } else {
      user.memories = (user.memories || []).filter(m => m.id !== id);
      await user.save();
    }
    req.flash('success', 'Memory deleted');
    res.redirect('/view-memories');
  } catch (err) {
    console.error('Error deleting memory:', err);
    req.flash('error', 'Failed to delete memory');
    res.redirect('/view-memories');
  }
});

app.post('/journal', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user; // Assuming the user is authenticated

    // Extract content and mood from the form input
    const { content, mood } = req.body;

    // Add the journal entry to the user's journal array
    const entry = { content, mood, timestamp: new Date() };
    user.journal = user.journal || [];
    user.journal.push(entry);

    // Persist depending on backend
    if (devStore) {
      await devStore.updateUser(user.id || user._id, { journal: user.journal });
    } else {
      await user.save();
    }

    // Redirect the user to the edit profile page or any other relevant page
    req.flash('success', 'Journal entry added successfully.');
    res.redirect('/journal'); // Redirect back to the journal page
  } catch (error) {
    req.flash('error', 'An error occurred while adding the journal entry.');
    res.redirect('/journal'); // Redirect back to the journal page in case of an error
  }
});
app.post('/journal-delete', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user; // Assuming the user is authenticated

    // Extract the ID of the journal entry to be deleted from the request body
    const entryId = req.body.entryId;
    // console.log(entryId.trim());
    // console.log(user.journal[0]._id.toString())

    // Find the index of the journal entry with the given ID in the user's journal array
    const entryIndex = user.journal.findIndex(entry => entry._id.toString() === entryId.trim());
    console.log('Entry index:', entryIndex);


    // Check if the journal entry exists
    if (entryIndex === -1) {
      // If not found, set flash message for error and redirect
      console.log('Journal entry not found');
      req.flash('error', 'Journal entry not found');
      return res.redirect('/journal');
    }

    // Remove the journal entry from the user's journal array
    user.journal.splice(entryIndex, 1);

    // Persist depending on backend
    if (devStore) {
      await devStore.updateUser(user.id || user._id, { journal: user.journal });
    } else {
      await user.save();
    }

    // Set flash message for success and redirect
    console.log('Journal entry deleted successfully');
    req.flash('success', 'Journal entry deleted successfully');
    res.redirect('/journal');
  } catch (error) {
    // Set flash message for error and redirect
    console.error('Error deleting journal entry:', error);
    req.flash('error', 'An error occurred while deleting the journal entry');
    res.redirect('/journal');
  }
});



app.get('/memory-games', checkAuthenticated, (req, res) => {
  res.render('memory-games.ejs');
});

app.post('/memory-games', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user; // Assuming the user is authenticated

    // Extract the selected game from the form input
    const selectedGame = req.body.gametype;

    // Log the selected game or perform any other necessary action
    console.log('Selected game:', selectedGame);

    // Redirect the user to the relevant page
    res.render('memory-games-all.ejs', { user: user, selectedGame: selectedGame });
  } catch (error) {
    console.error('Error processing memory game request:', error);
    req.flash('error', 'An error occurred while processing the memory game request.');
    res.redirect('/memory-games'); // Redirect to the memory games page in case of an error
  }
});






// Route to render the forum page
app.get('/forum', checkAuthenticated, async (req, res) => {
  try {
    // Assuming user is authenticated, retrieve the user from req.user
    const user = await req.user;

    // Fetch forum data from the database
    let forums = [];
    if (devStore) {
      const fs = require('fs').promises;
      const p = path.join(__dirname, 'data', 'forum.json');
      try {
        const txt = await fs.readFile(p, 'utf8');
        forums = JSON.parse(txt || '[]');
      } catch (e) {
        forums = [];
      }
    } else {
      forums = await Forum.find({}).populate('createdBy').exec();
    }
    res.render('forum.ejs', { user: user, forums: forums });
  } catch (error) {
    console.error('Error fetching forum data:', error);
    // Handle the error appropriately, for example, redirecting to an error page
    res.status(500).send('Internal Server Error');
  }
});


// POST request to create a new forum post
app.post('/forum', checkAuthenticated, async (req, res) => {
  try {
    // Extract data from the request body
    const { heading, description, tags } = req.body;
    const user = await req.user; // Assuming the user is authenticated

    // Create a new forum post instance
    let tagsArr = [];
    try { tagsArr = tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : []; } catch (e) { tagsArr = []; }
    if (devStore) {
      // Save to dev-store as a minimal object
      const fs = require('fs').promises;
      const p = path.join(__dirname, 'data', 'forum.json');
      let forums = [];
      try { const txt = await fs.readFile(p, 'utf8'); forums = JSON.parse(txt || '[]'); } catch (e) { forums = []; }
      const post = { _id: Date.now().toString(36), heading, description, createdBy: { username: user.username || user.email }, createdAt: new Date(), tags: tagsArr, comments: [] };
      forums.push(post);
      await fs.writeFile(p, JSON.stringify(forums, null, 2), 'utf8');
    } else {
      const newPost = new Forum({
        heading: heading,
        description: description,
        createdBy: user._id, // Assuming req.user contains the current user's information
        tags: tagsArr, // Split tags string into an array
      });
      await newPost.save();
    }

    // Redirect the user to the forum page or any other relevant page
    req.flash('success', 'Forum post created successfully.');
    res.redirect('/forum');
  } catch (error) {
    console.error('Error creating forum post:', error);
    req.flash('error', 'An error occurred while creating the forum post.');
    res.redirect('/forum'); // Redirect back to the forum page in case of an error
  }
});


app.post('/sendSOS', checkAuthenticated, async (req, res) => {
  try {
    // Get the authenticated user's information
    const user = await req.user;

    // Extract the emergency contact phone number from the user's information
    const emergencyContactPhone = user && user.emergencyContact && user.emergencyContact.phone;
    if (!emergencyContactPhone) {
      req.flash('error', 'No emergency contact phone configured for this user.');
      return res.redirect('/');
    }

    // Extract user's name and contact number
    const patientName = user.username;
    const patientContact = user.phone;

    if (!client) {
      console.warn('SOS requested but Twilio client is not configured.');
      req.flash('error', 'SOS not available: server not configured with Twilio credentials. Please set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER in your environment.');
      return res.redirect('/');
    }

    // Send SMS using Twilio
    await client.messages.create({
      body: `THIS IS AN SOS MESSAGE FROM HAVEN, from ${patientName}. Please contact immediately at ${patientContact}.`,
      from: process.env.TWILIO_FROM_NUMBER || '+15169812980', // Prefer env configured from number
      to: emergencyContactPhone
    });

    console.log('SOS sent successfully.');
    req.flash('success', 'SOS request sent successfully.');
    res.redirect('/');
  } catch (error) {
    console.error('Error sending SOS:', error);
    // Set error flash message
    req.flash('error', 'Failed to send SOS.');

    // Redirect to the home page or any other relevant page
    res.redirect('/');
  }
});




app.post('/comment', checkAuthenticated, async (req, res) => {
  try {
    // Extract data from the request body
    const { forumId, comment } = req.body;
    const user = await req.user; // Assuming the user is authenticated

    // Find the forum post by its ID
    const forumPost = await Forum.findById(forumId);

    if (!forumPost) {
      // If the forum post is not found, return an error response
      return res.status(404).send('Forum post not found');
    }

    // Create a new comment object
    const newComment = {
      content: comment,
      author: user.username, // Assuming req.user contains the current user's information
    };

    // Push the new comment to the comments array of the forum post
    forumPost.comments.push(newComment);

    // Save the updated forum post with the new comment
    await forumPost.save();

    // Redirect the user to the forum page or any other relevant page
    req.flash('success', 'Comment added successfully.');
    res.redirect('/forum');
  } catch (error) {
    console.error('Error adding comment:', error);
    req.flash('error', 'An error occurred while adding the comment.');
    res.redirect('/forum'); // Redirect back to the forum page in case of an error
  }
});




app.get('/physical-activity', checkAuthenticated, (req, res) => {
  res.render('home-physicalgame.ejs');
});

app.get('/todo', checkAuthenticated, (req, res) => {
  res.render('todo.ejs');
});


app.get('/edit-profile', (req, res) => {
  // Render the edit profile page, you can create a new EJS file for this
  req.user.then(user => {
    res.render('edit-profile.ejs', { user: user }); // Replace 'edit-profile' with the actual name of your EJS file  })
  });

});


app.post('/edit-profile', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user; // Assuming the user is authenticated

    // Update user details based on the form input
    user.username = req.body.name;
    user.age = req.body.age;
    user.email = req.body.email;
    user.emergencyContact.name = req.body.emergencyName;
    user.emergencyContact.email = req.body.emergencyEmail;
    user.emergencyContact.phone = req.body.emergencyPhone;
    // Persist the updated user to the selected backend
    if (devStore) {
      await devStore.updateUser(user.id || user._id, {
        username: user.username,
        age: user.age,
        email: user.email,
        emergencyContact: user.emergencyContact
      });
    } else {
      await user.save();
    }

    // Redirect the user to the profile page or any other relevant page
    req.flash('success', 'Profile updated successfully.');
    res.redirect('/edit-profile'); // Replace 'profile' with the actual route for viewing the profile
  } catch (error) {
    console.error('Error updating profile:', error);
    req.flash('error', 'An error occurred while updating the profile.');
    res.redirect('/edit-profile'); // Redirect back to the edit profile page in case of an error
  }
});


app.delete('/delete-account', checkAuthenticated, async (req, res) => {
  try {
    // Access the currently authenticated user
    const currentUser = await req.user;

    // Perform the deletion logic, for example using Mongoose
    await User.deleteOne({ _id: currentUser._id });

    // Log the user out after deleting the account
    req.logout((err) => {

      if (err) {
        return res.status(500).json({ success: false, message: 'Error logging out' });
      }
      res.json({ success: true, message: 'Account deleted successfully' });
    });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});
// Route for handling the profile update (POST request)


app.get('/statistics', checkAuthenticated, (req, res) => {
  req.user.then(user => {
    // console.log(user);
    res.render('statistics.ejs', { user: user });
  })

});


app.post('/statistics', checkAuthenticated, async (req, res) => {
  try {
    const patientData = req.body;
    const doctor = await req.user;
    console.log("Received patient data for statistics:", patientData);

  // Determine if the user is a caretaker
  const isCaretaker = doctor.userType === 'caretaker';

  // Combine patientData and additionalData into a single object
  const responseData = { user: patientData, isCaretaker };

    // Render the 'statistics.ejs' view with the response data
    res.render('statistics.ejs', responseData);
  } catch (error) {
    console.error('Error processing patient data for statistics:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});


// Add routes for accepting and declining connection requests
app.post('/accept-connection-request', checkAuthenticated, async (req, res) => {
  try {
  const caretaker = await req.user;
    const patientId = req.body.patientId;

    // Normalize to string
    const patientIdStr = String(patientId);
    const reqs = Array.isArray(caretaker.connectionRequests) ? caretaker.connectionRequests.map(r => String(r)) : [];
    const index = reqs.indexOf(patientIdStr);
    if (index === -1) {
      console.error('Connection request not found.');
      return res.status(400).send('Bad Request');
    }

    // Remove the patientId from connectionRequests and add it to connections (if not already)
    const newReqs = (caretaker.connectionRequests || []).filter(r => String(r) !== patientIdStr);
    const newConns = Array.isArray(caretaker.connections) ? caretaker.connections.map(c => String(c)) : [];
    if (!newConns.includes(patientIdStr)) newConns.push(patientIdStr);

    // Save changes
    if (devStore) {
      await devStore.updateUser(caretaker.id || caretaker._id, { connectionRequests: newReqs, connections: newConns });
      // update patient record: add caretaker to patient's connections
      const patient = await devStore.findById(patientIdStr);
      if (patient) {
        patient.connections = patient.connections || [];
        if (!patient.connections.map(c => String(c)).includes(String(caretaker.id || caretaker._id))) {
          patient.connections.push(String(caretaker.id || caretaker._id));
        }
        await devStore.updateUser(patientIdStr, { connections: patient.connections });
      }
    } else {
      // mongoose flow
      caretaker.connectionRequests = newReqs;
      caretaker.connections = caretaker.connections || [];
      if (!caretaker.connections.map(c => String(c)).includes(patientIdStr)) {
        caretaker.connections.push(patientIdStr);
      }
      await caretaker.save();
      const patient = await User.findById(patientIdStr);
      patient.connections = patient.connections || [];
      if (!patient.connections.map(c => String(c)).includes(String(caretaker._id))) {
        patient.connections.push(caretaker._id);
      }
      await patient.save();
    }

    res.redirect('/caretaker-home'); // Redirect to the caretaker's home page
  } catch (error) {
    console.error('Error accepting connection request:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/decline-connection-request', checkAuthenticated, async (req, res) => {
  try {
    const caretaker = await req.user;
    const patientId = req.body.patientId;

    // Normalize ids
    const pid = String(patientId);
    const newReqs = (caretaker.connectionRequests || []).filter(r => String(r) !== pid);

    // Save changes
    if (devStore) {
      await devStore.updateUser(caretaker.id || caretaker._id, { connectionRequests: newReqs });
    } else {
      caretaker.connectionRequests = newReqs;
      await caretaker.save();
    }

    res.redirect('/caretaker-home'); // Redirect to the caretaker's home page
  } catch (error) {
    console.error('Error declining connection request:', error);
    res.status(500).send('Internal Server Error');
  }
});



async function getCaretakerList(user) {
  // Assuming user.connections contains caretaker IDs
  const caretakerIds = user.connections || [];
  const caretakers = [];
  for (const request of caretakerIds) {
    if (devStore) {
      const c = await devStore.findById(request);
      if (c) caretakers.push({ doctor: c });
    } else {
      const c = await User.findById(request);
      if (c) caretakers.push({ doctor: c });
    }
  }
  return caretakers;
}


// Add a new route for the "Add Doctor" page
// Use the function in both routes
app.get('/add-doctor', checkAuthenticated, async (req, res) => {
  try {
    const user = await req.user;
    const doctors = await getCaretakerList(user);

    if (doctors.length > 0) {
      res.render('add-doctor.ejs', { user, doctors });
    } else {
      res.render('add-doctor.ejs', { user, doctors: [] });
    }
  } catch (error) {
    console.error('Error rendering add-doctor page:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});



// Handle doctor addition form submission
app.post('/add-doctor', checkAuthenticated, async (req, res) => {
  try {
    const patient = await req.user; // Retrieve the user from the database
    // console.log(patient);
    // console.log("Aaaaaaaaa");

    const { doctorName, doctorEmail } = req.body;

    // Check if the caretaker with the specified name and email exists
    // Support devStore (file-based) or MongoDB
    let doctor = null;
    let doctors = [];
    if (devStore) {
      const all = await readAllUsers();
      doctor = all.find(u => u.username === doctorName && u.email === doctorEmail && u.userType === 'caretaker');
      doctors = await getCaretakerList(patient);
      // If caretaker does not exist in devStore, create one (so caretakers can be added)
      if (!doctor) {
        const randomPass = Math.random().toString(36).slice(2, 10);
        const hashed = await bcrypt.hash(randomPass, 10);
        const created = await devStore.createUser({ username: doctorName, email: doctorEmail, password: hashed, userType: 'caretaker' });
        doctor = created;
      }
      const patientIdStr = (patient.id || patient._id).toString();
      const doctorIdStr = (doctor.id || doctor._id).toString();
      // Check existing connections
      if ((patient.connections || []).map(c=>c.toString()).includes(doctorIdStr)) {
        return res.render('add-doctor.ejs', { success: false, error: 'Caretaker is already in your connections', user: patient, doctors });
      }
      // Check if doctor already has a pending request
      const existingReqs = doctor.connectionRequests || [];
      if (existingReqs.map(r => r.toString()).includes(patientIdStr)) {
        return res.render('add-doctor.ejs', { success: false, error: 'Request already sent', user: patient, doctors });
      }
      // Add connection request to caretaker (do NOT automatically add to patient's connections)
      existingReqs.push(patientIdStr);
      await devStore.updateUser(doctorIdStr, { connectionRequests: existingReqs });
      // Optionally send email to caretaker if SMTP is configured
      if (nodemailer && process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
        try {
          const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: process.env.SMTP_PORT || 587, secure: false, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
          await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: doctor.email, subject: 'Connection request from patient', text: `User ${patient.username} has requested to connect with you on MEMO TRACK.` });
        } catch (e) {
          console.warn('Failed to send notification email:', e && e.message ? e.message : e);
        }
      }
      return res.render('add-doctor.ejs', { success: true, message: 'Request successfully sent', user: patient, doctors });
    } else {
      doctor = await User.findOne({ username: doctorName, email: doctorEmail, userType: 'caretaker' });
      doctors = await getCaretakerList(patient);
      if (!doctor) {
        return res.render('add-doctor.ejs', { success: false, error: 'Invalid caretaker name or email', user: patient, doctors });
      }
      const patientIdStr = (patient.id || patient._id).toString();
      const doctorIdStr = (doctor.id || doctor._id).toString();
      if ((patient.connections || []).map(c=>c.toString()).includes(doctorIdStr)) {
        return res.render('add-doctor.ejs', { success: false, error: 'Caretaker is already in your connections', user: patient, doctors });
      }
      const existingReqs = doctor.connectionRequests || [];
      if (existingReqs.map(r => r.toString()).includes(patientIdStr)) {
        return res.render('add-doctor.ejs', { success: false, error: 'Request already sent', user: patient, doctors });
      }
      existingReqs.push(patientIdStr);
      doctor.connectionRequests = existingReqs;
      await doctor.save();
      if (nodemailer && process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
        try {
          const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: process.env.SMTP_PORT || 587, secure: false, auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
          await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: doctor.email, subject: 'Connection request from patient', text: `User ${patient.username} has requested to connect with you on MEMO TRACK.` });
        } catch (e) {
          console.warn('Failed to send notification email:', e && e.message ? e.message : e);
        }
      }
      return res.render('add-doctor.ejs', { success: true, message: 'Request successfully sent', user: patient, doctors });
    }
  } catch (error) {
    console.error('Error adding caretaker:', error);
    res.render('add-doctor.ejs', { success: false, message: 'Internal Server Error', user: req.user, error: error.message, doctors: [] });
  }
});


app.delete('/remove-foreign-user', checkAuthenticated, async (req, res) => {
  try {
    const currentUser = await req.user; // Assuming req.user contains the current doctor's information

    // Extract foreignId from the request body
    const foreignId = req.body.foreignId;

    // Check if the foreignId is valid (you might want to add more validation)
    if (!foreignId) {
      return res.status(400).json({ success: false, message: 'Invalid foreignId' });
    }

    // Remove the foreignId from the user's connections
    currentUser.connections = currentUser.connections.filter(connection => connection.toString() !== foreignId);
    await currentUser.save();

    // Remove the user from the foreignId's connections
    const foreignUser = await User.findById(foreignId);
    if (foreignUser) {
      foreignUser.connections = foreignUser.connections.filter(connection => connection.toString() !== currentUser._id.toString());
      await foreignUser.save();
    }

    res.status(200).json({ success: true, message: 'Patient removed successfully' });
  } catch (error) {
    console.error('Error removing patient:', error);
    res.status(500).json({ success: false, message: 'Internal Server Error' });
  }
});




// Middleware to check if user is authenticated
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}




function checkNotAuthenticated(req, res, next) {
  if (!req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}





















app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
