require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve HTML files

// ---------- Helper: hash password ----------
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ---------- Models ----------

// Patient / User
const User = mongoose.model('User', {
  nationalId:  { type: String, required: true, unique: true },
  password:    { type: String, required: true },
  fullName:    { type: String, required: true },
  email:       { type: String },
  phone:       { type: String },
  bloodType:   { type: String },
  dateOfBirth: { type: String },
  address:     { type: String },
  credentialId: { type: String, index: true },   // biometric credential
  createdAt:   { type: Date, default: Date.now }
});

// Doctor
const Doctor = mongoose.model('Doctor', {
  nationalId:  { type: String, required: true, unique: true },
  password:    { type: String, required: true },
  fullName:    { type: String, required: true },
  specialization: { type: String },
  hospital:    { type: String },
  email:       { type: String },
  credentialId: { type: String, index: true },   // biometric credential
  createdAt:   { type: Date, default: Date.now }
});

// Medical Record
const MedicalRecord = mongoose.model('MedicalRecord', {
  patientNationalId: { type: String, required: true, index: true },
  doctorNationalId:  { type: String, required: true },
  doctorName:        { type: String },
  hospital:          { type: String },
  diagnosis:         { type: String, required: true },
  treatment:         { type: String },
  medications:       { type: String },
  notes:             { type: String },
  visitDate:         { type: Date, default: Date.now },
  createdAt:         { type: Date, default: Date.now }
});

// Admin
const Admin = mongoose.model('Admin', {
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

// ---------- Routes ----------

app.get('/', (req, res) => res.send('BioSafe API is running 🚀'));

// ================= ADMIN =================

app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'username and password are required' });

    const admin = await Admin.findOne({ username, password: hashPassword(password) });
    if (!admin) return res.status(401).json({ error: 'Invalid username or password' });

    res.json({
      message: 'Admin login successful',
      admin: { username: admin.username }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/register-patient', async (req, res) => {
  try {
    const { nationalId, password, fullName, email, phone, bloodType, dateOfBirth, address, credentialId } = req.body;
    if (!nationalId || !password || !fullName)
      return res.status(400).json({ error: 'nationalId, password and fullName are required' });
    if (!credentialId)
      return res.status(400).json({ error: 'Fingerprint scan is required' });

    const existing = await User.findOne({ nationalId });
    if (existing) return res.status(409).json({ error: 'A patient with this National ID already exists' });

    const user = await User.create({
      nationalId,
      password: hashPassword(password),
      fullName, email, phone, bloodType, dateOfBirth, address, credentialId
    });
    res.status(201).json({ message: 'Patient registered successfully', id: user._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/register-doctor', async (req, res) => {
  try {
    const { nationalId, password, fullName, specialization, hospital, email, credentialId } = req.body;
    if (!nationalId || !password || !fullName)
      return res.status(400).json({ error: 'nationalId, password and fullName are required' });
    if (!credentialId)
      return res.status(400).json({ error: 'Fingerprint scan is required' });

    const existing = await Doctor.findOne({ nationalId });
    if (existing) return res.status(409).json({ error: 'A doctor with this National ID already exists' });

    const doctor = await Doctor.create({
      nationalId,
      password: hashPassword(password),
      fullName, specialization, hospital, email, credentialId
    });
    res.status(201).json({ message: 'Doctor registered successfully', id: doctor._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/patients', async (req, res) => {
  try {
    const patients = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(patients);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/doctors', async (req, res) => {
  try {
    const doctors = await Doctor.find().select('-password').sort({ createdAt: -1 });
    res.json(doctors);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= USER (PATIENT) =================

app.post('/api/user/login', async (req, res) => {
  try {
    const { nationalId, password } = req.body;
    if (!nationalId || !password)
      return res.status(400).json({ error: 'nationalId and password are required' });

    const user = await User.findOne({ nationalId, password: hashPassword(password) });
    if (!user) return res.status(401).json({ error: 'Invalid National ID or password' });

    res.json({
      message: 'Login successful',
      user: {
        nationalId: user.nationalId,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        bloodType: user.bloodType,
        dateOfBirth: user.dateOfBirth,
        address: user.address
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Biometric login — patient
app.post('/api/user/login-biometric', async (req, res) => {
  try {
    const { credentialId } = req.body;
    if (!credentialId)
      return res.status(400).json({ error: 'credentialId is required' });

    const user = await User.findOne({ credentialId });
    if (!user) return res.status(404).json({ error: 'No account linked to this fingerprint' });

    res.json({
      message: 'Biometric login successful',
      user: {
        nationalId: user.nationalId,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        bloodType: user.bloodType,
        dateOfBirth: user.dateOfBirth,
        address: user.address
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/user/history/:nationalId', async (req, res) => {
  try {
    const records = await MedicalRecord.find({ patientNationalId: req.params.nationalId })
      .sort({ visitDate: -1 });
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= DOCTOR =================

app.post('/api/doctor/login', async (req, res) => {
  try {
    const { nationalId, password } = req.body;
    if (!nationalId || !password)
      return res.status(400).json({ error: 'nationalId and password are required' });

    const doctor = await Doctor.findOne({ nationalId, password: hashPassword(password) });
    if (!doctor) return res.status(401).json({ error: 'Invalid National ID or password' });

    res.json({
      message: 'Login successful',
      doctor: {
        nationalId: doctor.nationalId,
        fullName: doctor.fullName,
        specialization: doctor.specialization,
        hospital: doctor.hospital,
        email: doctor.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Biometric login — doctor
app.post('/api/doctor/login-biometric', async (req, res) => {
  try {
    const { credentialId } = req.body;
    if (!credentialId)
      return res.status(400).json({ error: 'credentialId is required' });

    const doctor = await Doctor.findOne({ credentialId });
    if (!doctor) return res.status(404).json({ error: 'No account linked to this fingerprint' });

    res.json({
      message: 'Biometric login successful',
      doctor: {
        nationalId: doctor.nationalId,
        fullName: doctor.fullName,
        specialization: doctor.specialization,
        hospital: doctor.hospital,
        email: doctor.email
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Register a new patient (Doctor only) — fingerprint required
app.post('/api/doctor/register-patient', async (req, res) => {
  try {
    const { nationalId, password, fullName, email, phone, bloodType, dateOfBirth, address, credentialId } = req.body;

    if (!nationalId || !password || !fullName)
      return res.status(400).json({ error: 'nationalId, password and fullName are required' });
    if (!credentialId)
      return res.status(400).json({ error: 'Fingerprint scan is required' });

    const existing = await User.findOne({ nationalId });
    if (existing) return res.status(409).json({ error: 'A patient with this National ID already exists' });

    const user = await User.create({
      nationalId,
      password: hashPassword(password),
      fullName, email, phone, bloodType, dateOfBirth, address, credentialId
    });

    res.status(201).json({ message: 'Patient added successfully', id: user._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/doctor/patient/:nationalId', async (req, res) => {
  try {
    const patient = await User.findOne({ nationalId: req.params.nationalId }).select('-password');
    if (!patient) return res.status(404).json({ error: 'Patient not found' });
    res.json(patient);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/doctor/records', async (req, res) => {
  try {
    const {
      patientNationalId, doctorNationalId, doctorName, hospital,
      diagnosis, treatment, medications, notes, visitDate
    } = req.body;

    if (!patientNationalId || !doctorNationalId || !diagnosis)
      return res.status(400).json({ error: 'patientNationalId, doctorNationalId and diagnosis are required' });

    const patient = await User.findOne({ nationalId: patientNationalId });
    if (!patient) return res.status(404).json({ error: 'Patient not found' });

    const record = await MedicalRecord.create({
      patientNationalId, doctorNationalId, doctorName, hospital,
      diagnosis, treatment, medications, notes,
      visitDate: visitDate || new Date()
    });
    res.status(201).json({ message: 'Medical record created', record });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/doctor/records/:doctorNationalId', async (req, res) => {
  try {
    const records = await MedicalRecord.find({ doctorNationalId: req.params.doctorNationalId })
      .sort({ visitDate: -1 });
    res.json(records);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------- Start Server & Connect to DB ----------

if (!process.env.MONGO_URL) {
  console.error('❌ ERROR: MONGO_URL is not defined in your .env file!');
  process.exit(1);
}

const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGO_URL)
  .then(async () => {
    console.log('✅ MongoDB connected');

    try {
      const exists = await Admin.findOne({ username: 'admin' });
      if (!exists) {
        await Admin.create({ username: 'admin', password: hashPassword('admin123') });
        console.log('✅ Default admin created → username: admin | password: admin123');
      } else {
        console.log('ℹ️  Admin account already exists');
      }
    } catch (err) {
      console.error('❌ Failed to seed admin:', err.message);
    }

    app.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    console.log('👉 Please check your .env file and ensure your database is accessible.');
  });