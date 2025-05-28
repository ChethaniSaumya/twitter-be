require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const queryString = require('query-string');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const { TwitterApi } = require('twitter-api-v2');
const Bottleneck = require('bottleneck');

const { FieldValue } = require('firebase-admin/firestore')
const { db } = require('./firebase.js');
const { authenticate } = require('./authenticate.js');
const admin = require('firebase-admin');

//const { Client, auth } = require("twitter-api-sdk");

const app = express();
const PORT = 3001;
const LOG_FILE = path.join(__dirname, 'user_logins.json');
const userPoints = {};
const userInvites = {};

const { Client } = require("twitter-api-sdk");

// ====== Twitter Rate Limit Config ======
const RATE_LIMITS = {
    likes: {
        max: 50,
        window: 15 * 60 * 1000 // 15 minutes in ms
    },
    follows: {
        max: 15,
        window: 15 * 60 * 1000
    }
};

// ====== Token Store ======
const tokenStore = new Map(); // username -> { accessToken, refreshToken, expiresAt }


// ====== Rate Limited Twitter Client ======

class RateLimitedTwitter {
    constructor() {
        this.likeLimiter = new Bottleneck({
            reservoir: RATE_LIMITS.likes.max,
            reservoirRefreshAmount: RATE_LIMITS.likes.max,
            reservoirRefreshInterval: RATE_LIMITS.likes.window
        });

        this.followLimiter = new Bottleneck({
            reservoir: RATE_LIMITS.follows.max,
            reservoirRefreshAmount: RATE_LIMITS.follows.max,
            reservoirRefreshInterval: RATE_LIMITS.follows.window
        });
    }

    async like(client, tweetId) {
        return this.likeLimiter.schedule(async () => {
            const me = await client.v2.me();
            return client.v2.like(me.data.id, tweetId);
        });
    }

    async follow(client, userId) {
        return this.followLimiter.schedule(async () => {
            const me = await client.v2.me();
            return client.v2.follow(me.data.id, userId);
        });
    }
}

const twitterRateLimiter = new RateLimitedTwitter();

// ====== Token Management ======
async function refreshTwitterToken(refreshToken) {
    try {
        const response = await axios.post('https://api.twitter.com/2/oauth2/token',
            new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: process.env.TWITTER_CLIENT_ID,
            }), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Authorization: `Basic ${Buffer.from(
                    `${process.env.TWITTER_CLIENT_ID}:${process.env.TWITTER_CLIENT_SECRET}`
                ).toString('base64')}`
            }
        });
        return response.data;
    } catch (error) {
        console.error('Token refresh failed:', error.response?.data || error.message);
        throw new Error('TOKEN_REFRESH_FAILED');
    }
}

async function getValidClient(username) {
    const tokens = tokenStore.get(username);
    if (!tokens) throw new Error('NO_TOKENS');

    // Refresh if expired
    if (tokens.expiresAt <= Date.now()) {
        try {
            const newTokens = await refreshTwitterToken(tokens.refreshToken);
            const updatedTokens = {
                accessToken: newTokens.access_token,
                refreshToken: newTokens.refresh_token,
                expiresAt: Date.now() + (newTokens.expires_in * 1000)
            };
            tokenStore.set(username, updatedTokens);


            return new TwitterApi(updatedTokens.accessToken);
        } catch (error) {
            throw new Error('REAUTH_NEEDED');
        }
    }

    return new TwitterApi(tokens.accessToken);
}
// now parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

var corsOptions = {
    origin: ['https://gonk-one.vercel.app', 'https://www.gonk.uk', 'https://gonk.uk', 'https://gonk-admin.vercel.app'],
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ["Content-Type"],
    credentials: true
};

// Twitter OAuth 2.0 Config
const TWITTER_CONFIG = {
    clientId: process.env.TWITTER_CLIENT_ID,
    redirectUri: 'https://gonk.uk/auth/callback',
    authUrl: 'https://twitter.com/i/oauth2/authorize',
    tokenUrl: 'https://api.twitter.com/2/oauth2/token',
    scope: ['tweet.read', 'users.read', 'offline.access', 'tweet.write'].join(' '),
    // This is for demo purposes only - in production, use proper secrets management
    clientSecret: process.env.TWITTER_CLIENT_SECRET,
};

app.options("/post-tweet", (req, res) => {
    // CORS preflight response
    res.sendStatus(200);
});

const lastTweet = {};

const TARGET_TWEET_ID = '1916613676599042465';

app.options("/like-tweet", (req, res) => {
    // CORS preflight response
    res.sendStatus(200);
});


function normalizeTextForTweet(text) {
    // append a zero-width space + timestamp so it *looks* the same
    return text + '\u200B' + Date.now();
}

const getTwitterClient = (access_token) => {
    // twitter-api-sdk expects the bearer token as the first argument
    return new Client(access_token);
};

app.post('/post-tweet', cors(corsOptions), async (req, res) => {
    const { access_token, username, text } = req.body;
    if (!access_token || !text || !username) {
        return res.status(400).json({ error: 'Access token, username and tweet text are required' });
    }

    try {
        if (lastTweet[username] === text) {
            return res.status(400).json({
                error: 'Duplicate tweet detected. Please modify your text and try again.'
            });
        }

        const tweetBody = text;
        const twitterClient = getTwitterClient(access_token);
        const response = await twitterClient.tweets.createTweet({ text: tweetBody });

        lastTweet[username] = text;

        // Record points in Firestore (100 points for posting a tweet)
        const pointsRecorded = await recordPoints(username, 25, `Tweet Posting`);

        if (!pointsRecorded) {
            // This case shouldn't normally happen since we're using a timestamp
            return res.status(400).json({
                error: 'Points for this tweet action were already awarded'
            });
        }

        res.json({
            success: true,
            tweet: response.data,
            tweetUrl: `https://twitter.com/${response.data.author_id}/status/${response.data.id}`,
            pointsAwarded: 25
        });

    } catch (error) {
        console.error("Tweet error:", error);
        if (error.error?.detail?.includes('duplicate content')) {
            return res.status(403).json({
                error: 'Duplicate content: please change your tweet before posting again.'
            });
        }
        res.status(error.status || 500).json({
            error: error.error?.detail || error.message
        });
    }
});

// Initialize log file
if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '[]');
}

app.use(cookieParser());
app.use(express.json());

// Generate a secure random string
const generateRandomString = (length) => {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
};

// ====== Protected Endpoint Handler ======
async function handleTwitterAction(req, res, action) {
    try {
        const { username } = req.body; // Get username from body instead of req.user
        if (!username) throw new Error('Username is required');

        const client = await getValidClient(username);
        const result = await action(client);
        res.json(result);

    }

    catch (error) {
        console.error('Twitter action failed:', error.message);

        if (error.message === 'NO_TOKENS') {
            return res.status(401).json({ error: 'Not authenticated with Twitter' });
        }
        if (error.message === 'REAUTH_NEEDED') {
            return res.status(401).json({ error: 'Reconnect Twitter account' });
        }
        if (error.message.includes('Rate limit exceeded')) {
            return res.status(429).json({
                error: 'Twitter rate limit reached',
                reset: new Date(Date.now() + error.retryAfter).toISOString()
            });
        }

        res.status(500).json({
            error: 'Twitter action failed',
            details: error.data?.errors || error.message
        });
    }
}
// (1) Initiate Twitter OAuth 2.0 flow
app.get('/auth/twitter', (req, res) => {
    const codeVerifier = generateRandomString(64);
    const codeChallenge = crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    const state = generateRandomString(16);

    const params = {
        response_type: 'code',
        client_id: TWITTER_CONFIG.clientId,
        redirect_uri: 'https://twitter-be-e2ow.onrender.com/auth/callback', // MUST point to backend
        scope: TWITTER_CONFIG.scope,
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    };

    res.cookie('code_verifier', codeVerifier, { httpOnly: true, secure: false }); // secure: false for localhost
    res.cookie('state', state, { httpOnly: true, secure: false });

    const authUrl = `${TWITTER_CONFIG.authUrl}?${queryString.stringify(params)}`;
    console.log("Redirecting to Twitter:", authUrl);
    res.redirect(authUrl);
});

app.get('/auth/callback', cors(corsOptions), async (req, res) => {
    console.log("Callback hit with query:", req.query);

    const { code, state } = req.query;
    const { code_verifier, state: storedState } = req.cookies;

    if (!code || !state || !storedState || state !== storedState) {
        console.error('Invalid callback:', { code, state, storedState });
        return res.status(400).send('Invalid OAuth state or missing code');
    }

    let username;

    try {
        // Exchange code for token
        const tokenResponse = await axios.post(
            TWITTER_CONFIG.tokenUrl,
            queryString.stringify({
                code,
                grant_type: 'authorization_code',
                client_id: TWITTER_CONFIG.clientId,
                redirect_uri: 'https://twitter-be-e2ow.onrender.com/auth/callback',
                code_verifier,
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Authorization: `Basic ${Buffer.from(
                        `${TWITTER_CONFIG.clientId}:${TWITTER_CONFIG.clientSecret}`
                    ).toString('base64')}`,
                },
            }
        );

        const { access_token, refresh_token, expires_in } = tokenResponse.data;
        console.log("Token exchange successful");

        // Get user info
        const userResponse = await axios.get('https://api.twitter.com/2/users/me', {
            headers: { Authorization: `Bearer ${access_token}` },
        });

        username = userResponse.data.data.username;
        const timestamp = new Date().toISOString();

        // Store tokens
        tokenStore.set(username, {
            accessToken: access_token,
            refreshToken: refresh_token,
            expiresAt: Date.now() + (expires_in * 1000)
        });

        // Log to JSON file
        const logData = JSON.parse(fs.readFileSync(LOG_FILE));
        logData.push({
            username,
            timestamp,
            tokenData: {
                access_token,
                refresh_token,
                expires_at: Date.now() + (expires_in * 1000)
            }
        });
        fs.writeFileSync(LOG_FILE, JSON.stringify(logData, null, 2));

        // NEW: Automatically award 25 points for account connection
        await recordPoints(username, 25, 'Connect Account');

        res.redirect(`https://gonk.uk/?username=${username}&access_token=${access_token}`);

    } catch (error) {
        console.error('Callback error:', {
            message: error.message,
            response: error.response?.data
        });

        if (username) {
            tokenStore.delete(username);
        }

        res.redirect('https://gonk.uk/?error=auth_failed');
    }
});

// (3) Get login history
app.get('/logins', cors(corsOptions), (req, res) => {
    try {
        const logData = JSON.parse(fs.readFileSync(LOG_FILE));
        res.json(logData);
    } catch (error) {
        console.error('Error reading log file:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const verifyTwitterAuth = async (req, res, next) => {
    try {
        const { username } = req.query;
        if (!username) {
            return res.status(401).json({ error: 'Twitter authentication required' });
        }

        // Initialize user points if not exists
        if (!userPoints[username]) {
            userPoints[username] = 0;
        }

        req.user = { username };
        next();
    } catch (error) {
        console.error('Auth verification error:', error);
        res.status(500).json({ error: 'Authentication check failed' });
    }
};

app.post('/refresh-token', cors(corsOptions), async (req, res) => {
    const { username } = req.body;

    try {
        const logData = JSON.parse(fs.readFileSync(LOG_FILE));
        const user = logData.find(u => u.username === username);

        if (!user || !user.tokenData?.refresh_token) {
            return res.status(401).json({ error: 'No refresh token available' });
        }

        const response = await axios.post(
            TWITTER_CONFIG.tokenUrl,
            queryString.stringify({
                grant_type: 'refresh_token',
                refresh_token: user.tokenData.refresh_token,
                client_id: TWITTER_CONFIG.clientId
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Authorization: `Basic ${Buffer.from(
                        `${TWITTER_CONFIG.clientId}:${TWITTER_CONFIG.clientSecret}`
                    ).toString('base64')}`,
                },
            }
        );

        const { access_token, refresh_token, expires_in } = response.data;
        const tokenData = {
            access_token,
            refresh_token,
            expires_at: Date.now() + (expires_in * 1000)
        };

        // Update the user's token data
        const updatedLogData = logData.map(u =>
            u.username === username ? { ...u, tokenData } : u
        );
        fs.writeFileSync(LOG_FILE, JSON.stringify(updatedLogData, null, 2));

        res.json({ access_token });

    } catch (error) {
        console.error('Token refresh failed:', error.response?.data || error.message);
        res.status(500).json({
            error: 'Token refresh failed',
            details: error.response?.data
        });
    }
});

//.............................. RETWEET - START ..............................//

app.options("/retweet", (req, res) => {
    // CORS preflight response
    res.sendStatus(200);
});

app.post('/retweet', cors(corsOptions), async (req, res) => {
    const { access_token, username, tweet_id } = req.body;

    if (!access_token || !tweet_id || !username) {
        return res.status(400).json({ error: 'Access token, username and tweet ID are required' });
    }

    try {
        const twitterClient = getTwitterClient(access_token);

        // First, get the user's Twitter ID
        const userData = await twitterClient.users.findMyUser();
        const userId = userData.data.id;

        // Retweet the tweet using the Twitter API
        const response = await twitterClient.tweets.usersIdRetweets(
            userId,
            {
                tweet_id: tweet_id
            }
        );

        // Record points in Firestore (50 points for retweet)
        const pointsRecorded = await recordPoints(username, 25, `Retweet Action`);

        if (!pointsRecorded) {
            return res.status(400).json({
                error: 'Points for this retweet action were already awarded'
            });
        }

        res.json({
            success: true,
            retweet: response.data,
            pointsAwarded: 25,
            tweetUrl: `https://twitter.com/i/status/${tweet_id}`
        });

    } catch (error) {
        console.error("Retweet error:", error);

        if (error.errors && error.errors.some(e => e.title === 'DuplicateRetweet')) {
            return res.status(400).json({
                error: 'You already retweeted this tweet'
            });
        }

        res.status(error.status || 500).json({
            error: error.errors?.[0]?.detail || error.message || 'Failed to retweet'
        });
    }
});

// Optional: Add an endpoint to check if a user has already retweeted a tweet
app.get('/retweet-check', cors(corsOptions), async (req, res) => {
    const { access_token, tweet_id } = req.query;

    if (!access_token || !tweet_id) {
        return res.status(400).json({ error: 'Access token and tweet ID are required' });
    }

    try {
        const twitterClient = getTwitterClient(access_token);

        // Get the user's Twitter ID
        const userData = await twitterClient.users.findMyUser();
        const userId = userData.data.id;

        // Get user's retweets
        const retweetsResponse = await twitterClient.tweets.usersIdTimeline(userId, {
            "tweet.fields": ["referenced_tweets"],
            "expansions": ["referenced_tweets.id"]
        });

        // Check if any of the tweets are retweets of the target tweet
        const hasRetweeted = retweetsResponse.data.some(tweet => {
            return tweet.referenced_tweets &&
                tweet.referenced_tweets.some(ref =>
                    ref.type === "retweeted" && ref.id === tweet_id
                );
        });

        res.json({ hasRetweeted });

    } catch (error) {
        console.error("Retweet check error:", error);
        res.status(error.status || 500).json({
            error: error.message || 'Failed to check retweet status'
        });
    }
});


//.............................. RETWEET - END ..............................//


//.............................. ADMIN PANEL - START............................
app.post('/assign-points', async (req, res) => {
  const { username, task, points, confirmation } = req.body;

  if (confirmation !== "True") {
    return res.status(400).json({ message: "Confirmation must be 'True'" });
  }

  try {
    const userRef = db.collection('users').doc(username);
    const userDoc = await userRef.get();

    let existingPoints = 0;

    if (userDoc.exists) {
      const userData = userDoc.data();
      const tasks = userData.tasks || {};
      existingPoints = tasks[task] || 0;
    }

    const newTotalPoints = existingPoints + points;

    // Update the user's points for the specific task
    await userRef.set({
      tasks: {
        [task]: newTotalPoints
      }
    }, { merge: true });

    // Remove from pending if it's a Follow Account task
    if (task === "Follow Account") {
      const pendingRef = db.collection('pending').doc(username);
      await pendingRef.delete();
    }

    res.json({
      message: `Added ${points} points to ${username} for ${task}. New total: ${newTotalPoints}`,
      points: newTotalPoints
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

//.............................. ADMIN PANEL - END.............................. 

async function recordPoints(username, points, task) {
    try {
        const userRef = db.collection('users').doc(username);
        const userDoc = await userRef.get();

        // Check if user already did this task
        const existingTasks = userDoc.exists ? userDoc.data().tasks || {} : {};
        if (existingTasks[task]) {
            return false; // Points already awarded for this task
        }

        // Add or merge task with points
        await userRef.set({
            tasks: {
                [task]: points
            }
        }, { merge: true });

        return true;
    } catch (err) {
        console.error('Error recording points:', err);
        return false;
    }
}

app.get('/api/tasks/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const userDoc = await db.collection('users').doc(username).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: 'User not found' });
    }

    const data = userDoc.data();
    const tasks = data.tasks || {};
    res.json({ tasks });
  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.get('/leaderboard', cors(corsOptions), async (req, res) => {
  try {
    const usersSnapshot = await db.collection('users').get();
    const leaderboardData = [];

    usersSnapshot.forEach(doc => {
      const userData = doc.data();
      const tasks = userData.tasks || {};
      
      // Calculate total points by summing all task points
      const totalPoints = Object.values(tasks).reduce((sum, points) => sum + points, 0);
      
      leaderboardData.push({
        username: doc.id,
        points: totalPoints,
        level: Math.floor(totalPoints / 200) + 1 // 1 level per 200 points
      });
    });

    // Sort by points (descending) and add ranks
    const sortedData = leaderboardData.sort((a, b) => b.points - a.points)
      .map((user, index) => ({
        ...user,
        rank: index + 1
      }));

    res.json(sortedData);
  } catch (error) {
    console.error("Error fetching leaderboard:", error);
    res.status(500).json({ error: "Failed to fetch leaderboard data" });
  }
});

app.post('/api/task-click', async (req, res) => {
  try {
    const { userId, username, task } = req.body;

    if (!userId || !task) {
      return res.status(400).json({ error: 'Missing userId or task' });
    }

    // Create a document reference
    const docRef = db.collection('pending').doc(userId);

    // Set the document with the task data
    await docRef.set({
      userId,
      username: username || null,
      status: `${task} - Pending`,
      task,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`Task recorded: ${task} for user ${userId}`);
    res.json({ message: 'Task recorded as pending', task, userId });

  } catch (error) {
    console.error('Error updating Firestore:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Optional: Add a route to check pending tasks
app.get('/api/pending/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const docRef = db.collection('pending').doc(userId);
    const doc = await docRef.get();

    if (doc.exists) {
      res.json({ exists: true, data: doc.data() });
    } else {
      res.json({ exists: false });
    }
  } catch (error) {
    console.error('Error fetching pending task:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add CORS options for the task-click route
app.options("/api/task-click", (req, res) => {
  res.sendStatus(200);
});

// Add this to your backend (server.js)
app.get('/api/pending-users', async (req, res) => {
  try {
    const snapshot = await db.collection('pending').get();
    const pendingUsers = [];
    
    snapshot.forEach(doc => {
      pendingUsers.push({
        userId: doc.id,
        ...doc.data()
      });
    });

    res.json(pendingUsers);
  } catch (error) {
    console.error('Error fetching pending users:', error);
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

app.post('/approve-pending', async (req, res) => {
  const { username } = req.body;

  try {
    // 1. Add points to users collection
    const userRef = db.collection('users').doc(username);
    await userRef.set({
      tasks: {
        "Follow Account": 25
      }
    }, { merge: true });

    // 2. Remove from pending collection
    const pendingRef = db.collection('pending').doc(username);
    await pendingRef.delete();

    res.json({ message: `Approved and assigned 25 points to ${username}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to approve pending user" });
  }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
