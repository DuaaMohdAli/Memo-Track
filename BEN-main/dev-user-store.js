const fs = require('fs').promises;
const path = require('path');

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');

async function ensureDataDir() {
  try {
    await fs.mkdir(dataDir, { recursive: true });
  } catch (e) {
    // ignore
  }
}

async function readUsers() {
  await ensureDataDir();
  try {
    const txt = await fs.readFile(usersFile, 'utf8');
    return JSON.parse(txt || '[]');
  } catch (e) {
    return [];
  }
}

async function writeUsers(users) {
  await ensureDataDir();
  await fs.writeFile(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

function makeId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function findByEmail(email) {
  const users = await readUsers();
  return users.find(u => String(u.email).toLowerCase() === String(email).toLowerCase()) || null;
}

async function findById(id) {
  const users = await readUsers();
  return users.find(u => u.id === String(id)) || null;
}

async function createUser(userData) {
  const users = await readUsers();
  const id = makeId();
  const newUser = Object.assign({ id, journal: [], memories: [], reminders: [], favorites: [], connections: [], connectionRequests: [], awards: [], games: {}, medications: [], assignedSongs: [] }, userData);
  users.push(newUser);
  await writeUsers(users);
  return newUser;
}

async function updateUser(id, patch) {
  const users = await readUsers();
  const idx = users.findIndex(u => u.id === String(id));
  if (idx === -1) return null;
  // merge favorites array if provided
  if (patch.favorites && Array.isArray(patch.favorites)) {
    users[idx].favorites = patch.favorites;
    delete patch.favorites;
  }
  // merge medications
  if (patch.medications && Array.isArray(patch.medications)) {
    users[idx].medications = patch.medications;
    delete patch.medications;
  }
  // merge assignedSongs
  if (patch.assignedSongs && Array.isArray(patch.assignedSongs)) {
    users[idx].assignedSongs = patch.assignedSongs;
    delete patch.assignedSongs;
  }
  users[idx] = Object.assign({}, users[idx], patch);
  await writeUsers(users);
  return users[idx];
}

module.exports = {
  findByEmail,
  findById,
  createUser,
  updateUser,
};
