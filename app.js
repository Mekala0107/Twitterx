const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, 'twitterClone.db');
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log(`Server Running at http://localhost:3000/`);
    });
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};
initializeDbAndServer();


// ---------------- AUTHENTICATION ----------------

// Register New User
app.post('/register/', async (req, res) => {
  try {
    const { username, password, name, gender } = req.body;

    const userCheckQuery = `SELECT * FROM user WHERE username = ?`;
    const dbUser = await db.get(userCheckQuery, [username]);

    if (dbUser) {
      return res.status(400).send('User already exists');
    }

    if (password.length < 6) {
      return res.status(400).send('Password is too short');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const registerUserQuery = `
      INSERT INTO user(username, password, name, gender)
      VALUES (?, ?, ?, ?)
    `;
    await db.run(registerUserQuery, [username, hashedPassword, name, gender]);
    res.send('User created successfully');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Login User
app.post('/login/', async (req, res) => {
  try {
    const { username, password } = req.body;

    const userCheckQuery = `SELECT * FROM user WHERE username = ?`;
    const dbUser = await db.get(userCheckQuery, [username]);

    if (!dbUser) {
      return res.status(400).send('Invalid user');
    }

    const isPasswordMatches = await bcrypt.compare(password, dbUser.password);
    if (!isPasswordMatches) {
      return res.status(400).send('Invalid password');
    }

    const payload = { username };
    const jwtToken = jwt.sign(payload, 'SECRET_KEY');
    res.send({ jwtToken });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const jwtToken = authHeader?.split(' ')[1];

  if (!jwtToken) {
    return res.status(401).send('Invalid JWT Token');
  }

  jwt.verify(jwtToken, 'SECRET_KEY', (error, payload) => {
    if (error) {
      return res.status(401).send('Invalid JWT Token');
    }

    req.username = payload.username; // safer than modifying headers
    next();
  });
};

// Middleware: Check if user follows tweet's author
const isUserFollowing = async (req, res, next) => {
  try {
    const { tweetId } = req.params;
    const { username } = req;

    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    const userId = dbUser.user_id;

    const tweetUserIdQuery = `SELECT user_id FROM tweet WHERE tweet_id = ?`;
    const tweetData = await db.get(tweetUserIdQuery, [tweetId]);

    if (!tweetData) {
      return res.status(404).send('Invalid Request');
    }

    const tweetUserID = tweetData.user_id;

    const followingQuery = `
      SELECT * FROM follower
      WHERE follower_user_id = ? AND following_user_id = ?
    `;
    const userFollowingData = await db.get(followingQuery, [userId, tweetUserID]);

    if (userFollowingData) {
      next();
    } else {
      res.status(403).send('Invalid Request');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
};


// ---------------- APIS ----------------

// API 3: Get user's feed
app.get('/user/tweets/feed/', authenticateToken, async (req, res) => {
  try {
    const { username } = req;
    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    const userId = dbUser.user_id;

    const query = `
      SELECT U.username, T.tweet, T.date_time AS dateTime
      FROM tweet AS T
      INNER JOIN follower AS F ON T.user_id = F.following_user_id
      INNER JOIN user AS U ON T.user_id = U.user_id
      WHERE F.follower_user_id = ?
      ORDER BY T.date_time DESC
      LIMIT 4
    `;
    const data = await db.all(query, [userId]);
    res.send(data);
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 4: Get users followed by the user
app.get('/user/following/', authenticateToken, async (req, res) => {
  try {
    const { username } = req;
    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    const userId = dbUser.user_id;

    const query = `
      SELECT U.name
      FROM follower AS F
      INNER JOIN user AS U ON F.following_user_id = U.user_id
      WHERE F.follower_user_id = ?
    `;
    const data = await db.all(query, [userId]);
    res.send(data);
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 5: Get followers of the user
app.get('/user/followers/', authenticateToken, async (req, res) => {
  try {
    const { username } = req;
    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    const userId = dbUser.user_id;

    const query = `
      SELECT U.name
      FROM follower AS F
      INNER JOIN user AS U ON F.follower_user_id = U.user_id
      WHERE F.following_user_id = ?
    `;
    const data = await db.all(query, [userId]);
    res.send(data);
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 6: Get tweet details
app.get('/tweets/:tweetId/', authenticateToken, isUserFollowing, async (req, res) => {
  try {
    const { tweetId } = req.params;
    const query = `
      SELECT
        T.tweet,
        COUNT(DISTINCT L.like_id) AS likes,
        COUNT(DISTINCT R.reply_id) AS replies,
        T.date_time AS dateTime
      FROM tweet AS T
      LEFT JOIN like AS L ON T.tweet_id = L.tweet_id
      LEFT JOIN reply AS R ON T.tweet_id = R.tweet_id
      WHERE T.tweet_id = ?
      GROUP BY T.tweet_id
    `;
    const data = await db.get(query, [tweetId]);
    res.send(data);
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 7: Get users who liked a tweet
app.get('/tweets/:tweetId/likes/', authenticateToken, isUserFollowing, async (req, res) => {
  try {
    const { tweetId } = req.params;
    const query = `
      SELECT U.username
      FROM like AS L
      NATURAL JOIN user AS U
      WHERE L.tweet_id = ?
    `;
    const data = await db.all(query, [tweetId]);
    const usernamesArray = data.map(each => each.username);
    res.send({ likes: usernamesArray });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 8: Get replies for a tweet
app.get('/tweets/:tweetId/replies/', authenticateToken, isUserFollowing, async (req, res) => {
  try {
    const { tweetId } = req.params;
    const query = `
      SELECT U.name, R.reply
      FROM reply AS R
      NATURAL JOIN user AS U
      WHERE R.tweet_id = ?
    `;
    const data = await db.all(query, [tweetId]);
    res.send({ replies: data });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 9: Get user's tweets with likes and replies count
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  try {
    const { username } = req;

    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    if (!dbUser) return res.status(404).json({ error: 'User not found' });

    const userId = dbUser.user_id;

    const query = `
      SELECT
        T.tweet,
        COUNT(DISTINCT L.like_id) AS likes,
        COUNT(DISTINCT R.reply_id) AS replies,
        T.date_time AS dateTime
      FROM tweet AS T
      LEFT JOIN like AS L ON T.tweet_id = L.tweet_id
      LEFT JOIN reply AS R ON T.tweet_id = R.tweet_id
      WHERE T.user_id = ?
      GROUP BY T.tweet_id
      ORDER BY T.date_time DESC
    `;
    const data = await db.all(query, [userId]);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// API 10: Post a new tweet
app.post('/user/tweets/', authenticateToken, async (req, res) => {
  try {
    const { tweet } = req.body;
    const { username } = req;

    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    if (!dbUser) return res.status(404).send('User not found');

    const userId = dbUser.user_id;
    const insertQuery = `INSERT INTO tweet(tweet, user_id) VALUES (?, ?)`;
    await db.run(insertQuery, [tweet, userId]);

    res.status(201).send('Created a Tweet');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

// API 11: Delete a tweet
app.delete('/tweets/:tweetId/', authenticateToken, async (req, res) => {
  try {
    const { tweetId } = req.params;
    const { username } = req;

    const getUserQuery = `SELECT user_id FROM user WHERE username = ?`;
    const dbUser = await db.get(getUserQuery, [username]);
    if (!dbUser) return res.status(404).send('User not found');

    const userId = dbUser.user_id;

    const userTweetsQuery = `SELECT tweet_id, user_id FROM tweet WHERE tweet_id = ?`;
    const tweetData = await db.get(userTweetsQuery, [tweetId]);

    if (!tweetData || tweetData.user_id !== userId) {
      return res.status(403).send('Invalid Request');
    }

    const deleteQuery = `DELETE FROM tweet WHERE tweet_id = ?`;
    await db.run(deleteQuery, [tweetId]);

    res.send('Tweet Removed');
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});


module.exports = app;

