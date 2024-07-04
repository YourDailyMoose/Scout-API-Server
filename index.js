const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const morgan = require('morgan');
const axios = require("axios");

const app = express();
const PORT = 3000;

// Use cors middleware with specific origin
const corsOptions = {
  origin: ['https://scoutbot.xyz', 'https://staff.scoutbot.xyz'],
  credentials: true, // Allow cookies to be sent across domains
  methods: ['GET', 'POST'],
  allowedHeaders: ['Authorization', 'Content-Type'],
};

// Apply CORS middleware globally except for specific routes
app.use((req, res, next) => {
  if (req.path.startsWith('/tickets/transcript')) {
    return next();
  }
  cors(corsOptions)(req, res, next);
});

// Use session middleware with secure, httpOnly, and sameSite cookies
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
    domain: 'scoutbot.xyz', // Set the Domain attribute to the parent domain
    httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
    sameSite: 'strict', // Only send cookies in requests that originate from the same site
    maxAge: 600000
  }
}));

app.set('view engine', 'ejs');

app.set('trust proxy', 1);
app.use(cookieParser());
app.use(express.json());
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  }
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
}));
app.use(morgan('combined')); // Ensure morgan is used for logging

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Add the /tickets/transcript/:ticketId route without CORS
app.get('/tickets/transcript/:ticketId', async (req, res) => {
  try {
    const ticketId = req.params.ticketId;
    const ticketData = await getTicketInfo(ticketId);

    if (ticketData === null) {
      return res.status(404).json({ error: '404 | Ticket Not Found' });
    }

    res.render('ticketTranscript', { ticket: ticketData });
  } catch (error) {
    console.error('Error fetching ticket:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/oauth/callback', async (req, res) => {
  try {
    console.log('Received OAuth callback')
    const { oauth2state, code } = req.body;

    if (oauth2state !== req.cookies.oauth2state) {
      console.log('Invalid state')
      return res.status(403).json({ error: 'Invalid state' });
    }

    // Exchange authorization code for access token
    const tokenResponse = await axios.post(
      `https://discordapp.com/api/oauth2/token`,
      `client_id=${process.env.SCOUT_CLIENT_ID}&client_secret=${process.env.SCOUT_CLIENT_SECRET}&grant_type=authorization_code&code=${code}&redirect_uri=${process.env.REDIRECT_URI}&scope=identify%20email%20guilds`
    );

    // Fetch user's data from Discord using the access token
    const access_token = tokenResponse.data.access_token;


    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: {
        authorization: `Bearer ${access_token}`,
      },
    });


    // Fetch user's guilds from Discord using the access token
    const guildsResponse = await axios.get('https://discord.com/api/users/@me/guilds', {
      headers: {
        authorization: `Bearer ${access_token}`,
      },
    });

    console.log(userResponse.data.id)

    const blacklistStatus = await isUserBlacklisted(userResponse.data.id)

    console.log('Blacklist status:', blacklistStatus);

    if (blacklistStatus) {
      return res.status(403).json({ message: "User attempting to authenticate is blacklisted", data: blacklistStatus });
    }


    // Generate a random key
    const dataKey = crypto.randomBytes(64).toString('hex');

    const payload = {
      dataKey: dataKey,
    };

    // Generate a JWT
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Store user data in MongoDB
    const userEntry = {
      dataKey: dataKey, // Store the random key to verify the user later
      access_token: access_token, // Store the access token to make requests to Discord API
      userData: userResponse.data,
      guilds: guildsResponse.data,
      lastUpdated: Date.now(),
      token: token, // Store the JWT
    };

    await oauthCallbackData(userEntry)

    // Return the access token, the random key, and the JWT to the client

    // Set the token and dataKey in the session data
    req.session.dataKey = dataKey;
    req.session.token = token;

    console.log('Saved session:', req.session); // Add this line
    // Return the access token, the random key, and the JWT to the client
    console.log('Authentication successful');
    res.json({ message: 'Authentication successful' });

  } catch (error) {
    if (error.response) {
      console.error('OAuth callback error:', error.response.data);
      res.status(error.response.status).json({ error: error.response.data });
    } else if (error.request) {
      console.error('No response was received', error.request);
      res.status(500).json({ error: 'No response was received' });
    } else {
      console.error('Request configuration error', error.message);
      res.status(500).json({ error: 'Request configuration error' });
    }
  }
});

async function authenticateToken(req, res, next) {
  const dataKey = req.session.dataKey;
  const token = req.session.token;

  console.log('Received request authenticate token');

  if (!dataKey) {
    console.log('No dataKey in session');
    return res.status(403).send('No datakey found in session.');
  }

  if (dataKey) {
    // Fetch the user entry from the database using the dataKey
    const userEntry = await fetchUserData(dataKey); // Use await here

    if (!userEntry || userEntry.token !== token) {
      console.log('No user entry or token mismatch');
      return res.status(404).send('No user entry to token mismatch');
    }

  }


  try {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log('JWT verify error:', err);
        return res.status(500).send('Token Internal Error');
      }
      req.user = user;
      next();
    });
  } catch (err) {
    console.log('Malformed JWT:', err);
    return res.status(500).send('Token Internal Error');
  }
}


app.get('/oauth/authorise', (req, res) => {
  console.log('Received request for state value');
  const state = crypto.randomBytes(16).toString('hex'); // Generate a new state value

  // Construct the authorization URL
  const params = new URLSearchParams({
    client_id: process.env.SCOUT_CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email guilds',
    state: state
  });
  const authUrl = `https://discord.com/api/oauth2/authorize?${params.toString()}`;

  // Send the authorization URL to the frontend
  res.cookie('oauth2state', state, { domain: '.scoutbot.xyz', httpOnly: true, sameSite: 'lax' });
  res.json({ authUrl: authUrl });
});


// Get user's data from MongoDB
app.get('/userdata', authenticateToken, async (req, res) => {
  try {

    console.log('Received request to get user data');

    const dataKey = req.session.dataKey;

    const userData = await fetchUserData(dataKey)

    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(userData);

  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




app.get('/bot/guilds', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to get bot guilds')

    let guildIds = req.query.guildIds; // Access the guild IDs from the query parameters

    // Convert guildIds to an array if it's not already
    if (!Array.isArray(guildIds)) {
      guildIds = [guildIds];
    }

    // Convert guildIds to Long instances
    const longGuildIds = guildIds.map(id => Long.fromString(id));

    const guilds = await getBotGuilds(longGuildIds);
    // Create a map of guildIDs to existence
    const existsMap = {};

    guildIds.forEach(id => {
      existsMap[id] = guilds.some(guild => guild._id.toString() === id);
    });

    res.json(existsMap);
  } catch (error) {
    console.error('Error getting guilds:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/guildsettings', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to get guild settings');
    const guildId = req.query.guildId;

    const guildSettings = await getGuildSettings(guildId);

    if (!guildSettings) {
      return res.status(404).json({ error: 'Guild not found' });
    }

    res.json(guildSettings);
  } catch (error) {
    console.error('Error getting guild settings:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/guild/useraccess', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to get user access to guild');
    const { guildId } = req.query; // Use req.query instead of req.params
    const dataKey = req.session.dataKey;

    console.log(guildId, dataKey)

    const userAccess = await getUserAccessToGuild(guildId, dataKey);
    console.log('User Access:', userAccess); // Log the userAccess

    res.json(userAccess);
  } catch (error) {
    console.error('Error getting user access to guild:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/guildsettings/module/enabled/update', authenticateToken, async (req, res) => {
  try {
    const { guildId, module, enabled } = req.body;

    const result = await updateGuildModuleSettings(guildId, module, enabled);

    res.json(result);
  } catch (error) {
    console.error('Error updating guild settings:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/guildsettings/serversettings/update', authenticateToken, async (req, res) => {
  try {
    const { guildId, setting, value } = req.body;

    // Call the updateServerSettings function
    const result = await updateServerSettings(guildId, setting, value);

    // Send a success response
    res.json({ success: true, message: 'Settings updated successfully', data: result });
  } catch (error) {
    // Send an error response
    res.status(500).json({ success: false, message: 'An error occurred while updating settings', error: error.message });
  }
});

app.post('/oauth/logout', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to logout');
    const dataKey = req.session.dataKey;

    const result = await logoutUser(dataKey);

    res.json(result);
  } catch (error) {
    console.error('Error logging out:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/bot/blacklists', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to get blacklists');
    const blacklists = await getBlacklists();

    res.json(blacklists);
  } catch (error) {
    console.error('Error getting blacklists:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/guild/roles', authenticateToken, async (req, res) => {
  try {
    console.log('Received request to get guild roles');
    const { guildId } = req.query;

    const roles = await axios.get(`https://discord.com/api/v9/guilds/${guildId}/roles`, {
      headers: {
        Authorization: `Bot ${process.env.TOKEN}`
      }
    });

    // Assuming roles.data is an array
    const sortedRoles = [...roles.data].sort((a, b) => b.position - a.position);

    res.json(sortedRoles);
  } catch (error) {
    console.error('Error getting guild roles:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


////////////////////////// -Staff API Endpoints- ///////////////////////////////////

app.get('/staff/oauth/authorise', cors(corsOptions), (req, res) => {
  console.log('Received request for state value');
  const state = crypto.randomBytes(16).toString('hex'); // Generate a new state value

  // Construct the authorization URL
  const params = new URLSearchParams({
    client_id: process.env.SCOUT_CLIENT_ID,
    redirect_uri: process.env.STAFF_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state: state
  });
  const authUrl = `https://discord.com/api/oauth2/authorize?${params.toString()}`;

  // Send the authorization URL to the frontend
  res.cookie('oauth2state', state, { domain: 'scoutbot.xyz', httpOnly: true, sameSite: 'lax' });
  res.json({ authUrl: authUrl });
});

async function authenticateStaffToken(req, res, next) {
  const dataKey = req.session.dataKey;
  const token = req.session.token;

  console.log('Received request authenticate token');

  if (!dataKey) {
    console.log('No dataKey in session');
    return res.status(403).send('No datakey found in session.');
  }

  if (dataKey) {
    // Fetch the user entry from the database using the dataKey
    const userEntry = await fetchStaffUserData(dataKey); // Use await here

    if (!userEntry || userEntry.token !== token) {
      console.log('No user entry or token mismatch');
      return res.status(404).send('No user entry to token mismatch');
    }

  }


  try {
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        console.log('JWT verify error:', err);
        return res.status(500).send('Token Internal Error');
      }
      req.user = user;
      next();
    });
  } catch (err) {
    console.log('Malformed JWT:', err);
    return res.status(500).send('Token Internal Error');
  }
}

app.post('/staff/oauth/callback', async (req, res) => {
  try {
    console.log('Received OAuth callback')
    const { oauth2state, code } = req.body;

    if (oauth2state !== req.cookies.oauth2state) {
      console.log('Invalid state')
      return res.status(403).json({ error: 'Invalid state' });
    }

    // Exchange authorization code for access token
    const tokenResponse = await axios.post(
      `https://discordapp.com/api/oauth2/token`,
      `client_id=${process.env.SCOUT_CLIENT_ID}&client_secret=${process.env.SCOUT_CLIENT_SECRET}&grant_type=authorization_code&code=${code}&redirect_uri=${process.env.STAFF_REDIRECT_URI}&scope=identify`
    );

    // Fetch user's data from Discord using the access token
    const access_token = tokenResponse.data.access_token;


    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: {
        authorization: `Bearer ${access_token}`,
      },
    });


    const presetRoles = {
      'productdevelopment': ['1211232192987013140', '1211223145156182096'],
      'publicrelations': ['1211231957384568842', '1211223145156182096'],
      'communitysafety': ['1211231075532144660', '1211223145156182096'],

      'headofproductdevelopment': ['1242468126314991616', '1242468469115715655', '1211232192987013140', '1211223145156182096'],
      'headofpublicrelations': ['1242468238873464833', '1242468469115715655', '1211231957384568842', '1211223145156182096'],
      'headofcommunitysafety': ['1242467891312332830', '1242468469115715655', '1211231075532144660', '1211223145156182096'],

      'headofoperations': ['1211249397183283312', '1242468469115715655', '1211223145156182096'],
      'ceo': ['736770508250546267', '1242468469115715655', '1211223145156182096']

    };

    const rolesData = await axios.get(`https://discord.com/api/v9/guilds/${process.env.SCOUT_SUPPORT_SERVER_ID}/members/${userResponse.data.id}`, {
      headers: {
        authorization: `Bot ${process.env.TOKEN}`,
      },
    });

    // Assign the user a role based on their role IDs
    let assignedRole = null;
    for (const [role, roleIds] of Object.entries(presetRoles)) {
      if (roleIds.every(roleId => rolesData.data.roles.includes(roleId))) {
        assignedRole = role;
        break;
      }
    }
    console.log(userResponse.data.id)
    console.log(assignedRole)




    // Generate a random key
    const dataKey = crypto.randomBytes(64).toString('hex');

    const payload = {
      dataKey: dataKey,
    };

    // Generate a JWT
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Store user data in MongoDB
    const userEntry = {
      dataKey: dataKey, // Store the random key to verify the user later
      access_token: access_token, // Store the access token to make requests to Discord API
      userData: userResponse.data,
      assignedRole: assignedRole,
      lastUpdated: Date.now(),
      token: token, // Store the JWT
    };

    await staffOauthCallbackData(userEntry)

    // Return the access token, the random key, and the JWT to the client

    // Set the token and dataKey in the session data
    req.session.dataKey = dataKey;
    req.session.token = token;

    console.log('Saved session:', req.session); // Add this line
    // Return the access token, the random key, and the JWT to the client
    console.log('Authentication successful');
    res.json({ message: 'Authentication successful' });

  } catch (error) {
    if (error.response) {
      console.error('OAuth callback error:', error.response.data);
      res.status(error.response.status).json({ error: error.response.data });
    } else if (error.request) {
      console.error('No response was received', error.request);
      res.status(500).json({ error: 'No response was received' });
    } else {
      console.error('Request configuration error', error.message);
      res.status(500).json({ error: 'Request configuration error' });
    }
  }
});

app.get('/staff/userdata', authenticateStaffToken, async (req, res) => {
  try {

    console.log('Received request to get staff user data');

    const dataKey = req.session.dataKey;
    console.log(dataKey)

    const userData = await fetchStaffUserData(dataKey)

    if (!userData) {
      console.log('No User Data Found', dataKey)
      return res.status(404).json({ error: 'User data entry not found.' });
    }

    res.json(userData);

  } catch (error) {
    console.error('Error getting user data:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 