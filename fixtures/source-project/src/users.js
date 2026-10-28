// Planted issue SP-1: SQL built by string concatenation (A05, CWE-89)
const { connection } = require('./db-pool');

function findUser(req) {
  const userId = req.params.id;
  const query = 'SELECT id, name, email FROM users WHERE id = ' + userId;
  return connection.query(query);
}

module.exports = { findUser };
