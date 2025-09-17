const express = require('express')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

const dbPath = path.join(__dirname, 'twitterClone.db')
let db = null

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log(`Server Running at http://localhost:3000/`)
    })
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}
initializeDbAndServer()

// API: Register New User
app.post('/register/', async (request, response) => {
  const {username, password, name, gender} = request.body

  const userCheckQuery = `
    SELECT * FROM user WHERE username = '${username}';`
  const dbUser = await db.get(userCheckQuery)
  if (dbUser === undefined) {
    if (password.length < 6) {
      response.status(400)
      response.send('Password is too short')
    } else {
      const hashPassword = await bcrypt.hash(password, 10)
      const registerUserQuery = `
            INSERT INTO 
                user(username, password, name, gender)
            VALUES
                ('${username}', '${hashPassword}', '${name}', '${gender}');`
      await db.run(registerUserQuery)
      response.send('User created successfully')
    }
  } else {
    response.status(400)
    response.send('User already exists')
  }
})

// Authentication Middleware
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  const jwtToken = authHeader?.split(' ')[1];

  if (!jwtToken) {
    return response.status(401).send('Invalid JWT Token');
  }

  jwt.verify(jwtToken, 'SECRET_KEY', (error, payload) => {
    if (error) {
      return response.status(401).send('Invalid JWT Token');
    }

    // Attach username to request
    request.headers.username = payload.username;
    next();
  });
};


// Middleware to check if user follows the tweet's author
const isUserFollowing = async (request, response, next) => {
  const {tweetId} = request.params
  const {username} = request.headers

  const getUserQuery = `SELECT user_id FROM user WHERE username = '${username}';`
  const dbUser = await db.get(getUserQuery)
  const userId = dbUser['user_id']

  const tweetUserIdQuery = `SELECT user_id FROM tweet WHERE tweet_id = ${tweetId}`
  const tweetData = await db.get(tweetUserIdQuery)

  if (tweetData === undefined) {
    response.status(404)
    response.send('Invalid Request')
    return
  }

  const tweetUserID = tweetData['user_id']

  const followingQuery = `
    SELECT * FROM follower
    WHERE follower_user_id = ${userId} AND following_user_id = ${tweetUserID};`
  const userFollowingData = await db.get(followingQuery)

  if (userFollowingData !== undefined) {
    next()
  } else {
    response.status(401)
    response.send('Invalid Request')
  }
}

// API: Login User
app.post('/login/', async (request, response) => {
  const {username, password} = request.body
  const userCheckQuery = `SELECT * FROM user WHERE username = '${username}';`
  const dbUser = await db.get(userCheckQuery)
  if (dbUser === undefined) {
    response.status(400)
    response.send('Invalid user')
  } else {
    const isPasswordMatches = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatches) {
      const payLoad = {username}
      const jwtToken = jwt.sign(payLoad, 'SECRET_KEY')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid password')
    }
  }
})

// API - 3: Get user's feed
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  const {username} = request.headers
  const getUserQuery = `
    SELECT user_id FROM user WHERE username = '${username}';`
  const dbUser = await db.get(getUserQuery)
  const userId = dbUser['user_id']

  const query = `
    SELECT T2.username, T1.tweet, T1.date_time As dateTime
    FROM tweet AS T1
    INNER JOIN follower AS T3 ON T1.user_id = T3.following_user_id
    INNER JOIN user AS T2 ON T1.user_id = T2.user_id
    WHERE T3.follower_user_id = ${userId}
    ORDER BY T1.date_time DESC
    LIMIT 4;`

  const data = await db.all(query)
  response.send(data)
})

// API - 4: Get users followed by the user
app.get('/user/following/', authenticateToken, async (request, response) => {
  const {username} = request.headers
  const getUserQuery = `
    SELECT user_id FROM user WHERE username = '${username}';`
  const dbUser = await db.get(getUserQuery)
  const userId = dbUser['user_id']

  const query = `
    SELECT T2.name
    FROM follower AS T1 INNER JOIN user AS T2
    ON T1.following_user_id = T2.user_id
    WHERE T1.follower_user_id = ${userId};`

  const data = await db.all(query)
  response.send(data)
})

// API 5: Get followers of the user
app.get('/user/followers/', authenticateToken, async (request, response) => {
  const {username} = request.headers
  const getUserQuery = `
    SELECT user_id FROM user WHERE username = '${username}';`
  const dbUser = await db.get(getUserQuery)
  const userId = dbUser['user_id']

  const query = `
    SELECT T2.name
    FROM follower AS T1 INNER JOIN user AS T2
    ON T1.follower_user_id = T2.user_id
    WHERE T1.following_user_id = ${userId};`

  const data = await db.all(query)
  response.send(data)
})

// API 6: Get tweet details
app.get(
  '/tweets/:tweetId/',
  authenticateToken,
  isUserFollowing,
  async (request, response) => {
    const {tweetId} = request.params
    const query = `
      SELECT
        T.tweet,
        COUNT(DISTINCT L.like_id) AS likes,
        COUNT(DISTINCT R.reply_id) AS replies,
        T.date_time AS dateTime
      FROM
        tweet AS T
        LEFT JOIN like AS L ON T.tweet_id = L.tweet_id
        LEFT JOIN reply AS R ON T.tweet_id = R.tweet_id
      WHERE
        T.tweet_id = ${tweetId}
      GROUP BY T.tweet_id;`

    const data = await db.get(query);
    response.send(data);
  },
);

// API 7: Get users who liked a tweet
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  isUserFollowing,
  async (request, response) => {
    const {tweetId} = request.params
    const query = `
        SELECT T2.username
        FROM like AS T1 NATURAL JOIN user AS T2
        WHERE T1.tweet_id = ${tweetId};`

    const data = await db.all(query)
    const usernamesArray = data.map(each => each.username)

    response.send({likes: usernamesArray})
  },
)

// API 8: Get replies for a tweet
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  isUserFollowing,
  async (request, response) => {
    const {tweetId} = request.params
    const query = `
        SELECT T2.name, T1.reply
        FROM reply AS T1 NATURAL JOIN user AS T2
        WHERE T1.tweet_id = ${tweetId};`

    const data = await db.all(query)
    response.send({replies: data})
  },
)

// API 9: Get user's tweets with likes and replies count
app.get('/user/tweets/', authenticateToken, async (req, res) => {
  try {
    const { username } = req.headers;

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
      FROM
        tweet AS T
        LEFT JOIN like AS L ON T.tweet_id = L.tweet_id
        LEFT JOIN reply AS R ON T.tweet_id = R.tweet_id
      WHERE
        T.user_id = ?
      GROUP BY
        T.tweet_id
      ORDER BY
        T.date_time DESC;
    `;

    const data = await db.all(query, [userId]);
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// API 10: Post a new tweet
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  const {tweet} = request.body
  const {username} = request.headers
  const getUserQuery = `
    SELECT user_id FROM user WHERE username = '${username}';`
  const dbUser = await db.get(getUserQuery)
  const userId = dbUser['user_id']

  const query = `
    INSERT INTO 
        tweet(tweet, user_id)
    VALUES ('${tweet}', ${userId});`
  await db.run(query)
  response.send('Created a Tweet')
})

// API 11: Delete a tweet
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    const {tweetId} = request.params
    const {username} = request.headers
    const getUserQuery = `
      SELECT user_id FROM user WHERE username = '${username}';`
    const dbUser = await db.get(getUserQuery)
    const userId = dbUser['user_id']

    const userTweetsQuery = `
      SELECT tweet_id, user_id
      FROM tweet
      WHERE tweet_id = ${tweetId};`
    const tweetData = await db.get(userTweetsQuery);

    if (tweetData === undefined || tweetData.user_id !== userId) {
      response.status(401)
      response.send('Invalid Request')
    } else {
      const query = `
        DELETE FROM tweet
        WHERE tweet_id = ${tweetId};`
      await db.run(query)
      response.send('Tweet Removed')
    }
  },
)

module.exports = app;
