const { MongoClient, ServerApiVersion, ObjectId, Long } = require('mongodb');
const { DateTime } = require('luxon');
const { v4: uuidv4 } = require('uuid');

let db;

// Path to your certificate
const credentials = process.env.PATH_TO_CERT;

// MongoDB connection 
const client = new MongoClient(process.env.MONGODB_URI, {
    tlsCertificateKeyFile: credentials,
    serverApi: ServerApiVersion.v1,
});

async function connectToDatabase() {
    try {
        await client.connect();
        db = client.db('botData');

        // Registering the close event listener
        client.on('close', () => {
            console.log('MongoDB connection closed');
        });
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
    }
}

function getDB() {
    return db;
}



async function wipeGuildSettings(guildId) {
    try {
        await db.collection('botSettings').deleteOne({ _id: guildId });
        return (true)
    } catch (error) {
        console.error(`Error deleting guild ${guildId} from the database:`, error);
        return (false)
    }
}



async function getGuildSettings(guildId) {
    if (!guildId) {
        console.error('Error: guildId is undefined');
        return;
    }

    const longGuildId = Long.fromString(guildId);
    return await db.collection('botSettings').findOne({ _id: longGuildId });
}

async function isUserBlacklisted(userId) {
    try {
        const collection = db.collection("blacklistData");
        const query = { type: "user", userid: userId, active: true };
        const blacklistedUser = await collection.findOne(query);

        return blacklistedUser;
    } catch (err) {
        console.error("Error checking if user is blacklisted:", err);
        return null;
    }
}

async function oauthCallbackData(userEntry) {

    const collection = client.db('websiteData').collection("userData");

    // Update or insert user data in MongoDB
    await collection.updateOne(
        { "userData.id": userEntry.userData.id }, // Filter by user ID
        { $set: userEntry }, // Update or set the user data
        { upsert: true } // Create a new document if no documents match the filter
    );
}

async function fetchUserData(dataKey) {

    const collection = client.db('websiteData').collection("userData");

    const userData = await collection.findOne({ dataKey });


    if (!userData) {
        return null;
    } else {
        return userData;
    }

}

async function getBotGuilds(longGuildIds) {
    const collection = client.db('botData').collection("botSettings");

    const guilds = await collection.find({ _id: { $in: longGuildIds } }).toArray();

    return guilds;
}

async function updateGuildModuleSettings(guildId, module, enabled) {
    const collection = client.db('botData').collection('botSettings');

    // Convert guildId to a Long instance
    const longGuildId = Long.fromString(guildId);

    const currentSettings = await collection.findOne({ _id: longGuildId });

    if (currentSettings && currentSettings.modules[module] && currentSettings.modules[module].enabled === enabled) {
        return { message: 'No changes were made' };
    }

    const result = await collection.updateOne(
        { _id: longGuildId },
        { $set: { [`modules.${module}.enabled`]: enabled } },
        { upsert: true }
    );

    return { status: 'success' };
}

async function getUserAccessToGuild(guildId, dataKey) {
    const collection = client.db('websiteData').collection("userData");
    const user = await collection.findOne({ dataKey });

    if (!user) {
        return { status: 'User not found' };
    }

    const guild = user.guilds.find((guild) => guild.id === guildId);

    if (!guild) {
        return { status: 'Guild not found' };
    }

    const isOwner = guild.owner;
    const isAdmin = (guild.permissions & 0x8) === 0x8 || (guild.permissions & 0x20) === 0x20;

    let role;
    if (isOwner) {
        role = 'Owner';
    } else if (isAdmin) {
        role = 'Admin';
    } else {
        role = 'None';
    }
    return { role };
}

async function logoutUser(dataKey) {
    const collection = client.db('websiteData').collection("userData");

    const result = await collection.updateOne(
        { dataKey: dataKey }, // Filter
        { $set: { token: null, dataKey: null } } // Update
    );

    return result;
}

async function isModuleEnabled(guildId, moduleName) {
    // Get the guild settings document for the given guild ID
    const longGuildId = Long.fromString(guildId);
    const guildSettings = await db.collection('botSettings').findOne({ _id: longGuildId });

    if (!guildSettings) {
        throw new Error('Guild Settings not Found for Module Check')
    }

    // Check if the module exists in the guild settings
    if (!(moduleName in guildSettings.modules)) {
        throw new Error(`Module ${moduleName} does not exist in guild settings.`);
    }

    // Get the module settings
    const moduleSettings = guildSettings.modules[moduleName];

    // Otherwise, return the value of the "enabled" field
    return typeof moduleSettings === 'boolean' ? moduleSettings : moduleSettings.enabled;
}

async function updateServerSettings(guildId, setting, value) {
    const longGuildId = Long.fromString(guildId);
    const guildSettings = await db.collection('botSettings').findOne({ _id: longGuildId });

    if (!guildSettings) {
        throw new Error('Guild Settings not Found for Module Check')
    }

    if (setting === 'colours') {
        if (typeof value !== 'object' || !('primary' in value) || !('success' in value) || !('error' in value) || !('warning' in value) || !('special' in value)) {
            throw new Error('Invalid value for colours setting');
        }

        await db.collection('botSettings').updateOne(
            { _id: longGuildId },
            { $set: { 'serverSettings.colours': value } }
        );
    } else if (setting === 'timezone') {
        if (typeof value !== 'string') {
            throw new Error('Invalid value for timezone setting');
        }

        await db.collection('botSettings').updateOne(
            { _id: longGuildId },
            { $set: { 'serverSettings.timezone': value } }
        );
    } else {
        throw new Error('Invalid setting');
    }
}

async function getBlacklists() {
    const collection = db.collection("blacklistData");
    const blacklists = await collection.find({}).toArray();
    return blacklists;
}

async function getTicketInfo(ticketId) {
    try {
        const data = await db.collection('supportTickets').findOne({ _id: Long.fromString(ticketId) });
        return data;
    } catch {
        return null;
    }
}

async function staffOauthCallbackData(userEntry) {
    const collection = client.db('websiteData').collection("staffUserData");

    // Update or insert user data in MongoDB
    await collection.updateOne(
        { "userData.id": userEntry.userData.id }, // Filter by user ID
        { $set: userEntry }, // Update or set the user data
        { upsert: true } // Create a new document if no documents match the filter
    );
}

async function fetchStaffUserData(dataKey) {

    const collection = client.db('websiteData').collection("staffUserData");

    const userData = await collection.findOne({ dataKey });


    if (!userData) {
        return null;
    } else {
        return userData;
    }

}

async function closeDatabaseConnection() {
    if (client) {
        try {
            await client.close();
            console.log('Disconnected from MongoDB for shutdown');
        } catch (error) {
            console.error('Error disconnecting from MongoDB:', error);
            throw error;
        }
    } else {
        console.log('MongoDB client is not provided or not initialized.');
    }
}

async function saveMetricsData(data) {
    try {
        const collection = db.collection("metricsData");
        await collection.insertOne(data);
        console.log('Data successfully saved to MongoDB');
    } catch (error) {
        console.error('Error saving data to MongoDB:', error);
        throw error; // Rethrowing the error might be optional based on how you want to handle it.
    }
}


async function getGuildBotColours(guildId) {
    const longGuildId = Long.fromString(guildId);
    const guild = await db.collection('botSettings').findOne({ _id: longGuildId });
    return guild.serverSettings.colours;
}

module.exports = {
    connectToDatabase,
    getDB,
    wipeGuildSettings,
    getGuildSettings,
    isUserBlacklisted,
    oauthCallbackData,
    fetchUserData,
    getBotGuilds,
    updateGuildModuleSettings,
    getUserAccessToGuild,
    logoutUser,
    isModuleEnabled,
    updateServerSettings,
    getTicketInfo,
    staffOauthCallbackData,
    fetchStaffUserData,
    saveMetricsData,
    closeDatabaseConnection,
    getGuildBotColours

}