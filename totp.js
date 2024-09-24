const crypto = require('crypto');
const fs = require('fs');
const readlineSync = require('readline-sync');
const clipboardy = require('clipboardy');

const ACCOUNTS_FILE = 'accounts.json';
const PASSWORD_FILE = 'password.json';

function generateSalt() {
    return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, hash, salt) {
    const hashToVerify = hashPassword(password, salt);
    return hashToVerify === hash;
}

function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text, key) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts.shift(), 'hex');
    const encryptedText = Buffer.from(textParts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedText, null, 'utf8') + decipher.final('utf8');
    return decrypted;
}

function loadAccounts(key) {
    if (!fs.existsSync(ACCOUNTS_FILE)) {
        return [];
    }
    const data = fs.readFileSync(ACCOUNTS_FILE, 'utf8');
    const decryptedData = decrypt(data, key);
    return JSON.parse(decryptedData);
}

function saveAccounts(accounts, key) {
    try {
        const jsonData = JSON.stringify(accounts, null, 2);
        const encryptedData = encrypt(jsonData, key);
        fs.writeFileSync(ACCOUNTS_FILE, encryptedData);
    } catch (error) {
        console.error('Error saving accounts:', error.message);
    }
}

function base32Decode(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let binary = '';

    for (let char of base32) {
        const value = base32Chars.indexOf(char);
        if (value === -1) continue;
        binary += value.toString(2).padStart(5, '0');
    }

    const bytes = [];
    for (let i = 0; i < binary.length; i += 8) {
        bytes.push(parseInt(binary.slice(i, i + 8), 2));
    }

    return Buffer.from(bytes);
}

function generateTOTP(secret, timeStep = 30, digits = 6) {
    const key = base32Decode(secret);
    const time = Math.floor(Date.now() / 1000 / timeStep);
    const timeBuffer = Buffer.alloc(8);
    
    timeBuffer.writeUInt32BE(0, 0);
    timeBuffer.writeUInt32BE(time, 4);
    
    const hmac = crypto.createHmac('sha1', key);
    hmac.update(timeBuffer);
    const hmacResult = hmac.digest();

    const offset = hmacResult[hmacResult.length - 1] & 0xf;
    const code = (hmacResult.readUInt32BE(offset) & 0x7fffffff) % Math.pow(10, digits);
    
    return String(code).padStart(digits, '0');
}

function promptForPassword() {
    let password;
    if (fs.existsSync(PASSWORD_FILE)) {
        const { hash, salt } = JSON.parse(fs.readFileSync(PASSWORD_FILE));
        password = readlineSync.question('Enter your password: ', { hideEchoBack: true });
        if (!verifyPassword(password, hash, salt)) {
            console.log('Invalid password. Exiting.');
            process.exit(1);
        }
    } else {
        password = readlineSync.question('Set your new password: ', { hideEchoBack: true });
        const salt = generateSalt();
        const hash = hashPassword(password, salt);
        fs.writeFileSync(PASSWORD_FILE, JSON.stringify({ hash, salt }));
        console.log('Password set successfully.');
    }
    return crypto.scryptSync(password, 'salt', 32);
}

function addAccount(key) {
    const accounts = loadAccounts(key);
    const accountName = readlineSync.question('Enter account name: ');
    const secret = readlineSync.question('Enter base32 secret: ');

    accounts.push({ name: accountName, secret });
    saveAccounts(accounts, key);
    console.log('Account saved.');
}

function removeAccount(key) {
    const accounts = loadAccounts(key);
    if (accounts.length === 0) {
        console.log('No accounts found to remove.');
        return;
    }

    accounts.forEach((account, index) => {
        console.log(`${index + 1}: ${account.name}`);
    });

    const choice = readlineSync.questionInt('Select an account to remove by number: ') - 1;
    if (choice < 0 || choice >= accounts.length) {
        console.log('Invalid choice.');
        return;
    }

    accounts.splice(choice, 1);
    saveAccounts(accounts, key);
    console.log('Account removed successfully.');
}

function generateOTP(key) {
    const accounts = loadAccounts(key);
    if (accounts.length === 0) {
        console.log('No accounts found. Please add an account first.');
        return;
    }

    accounts.forEach((account, index) => {
        console.log(`${index + 1}: ${account.name}`);
    });

    const choice = readlineSync.questionInt('Select an account by number: ') - 1;
    if (choice < 0 || choice >= accounts.length) {
        console.log('Invalid choice.');
        return;
    }

    const otp = generateTOTP(accounts[choice].secret);
    console.log(`Your OTP for ${accounts[choice].name}: ${otp}`);

    clipboardy.writeSync(otp);
    console.log('OTP copied to clipboard.');
}

function main() {
    const key = promptForPassword();

    while (true) {
        console.log('1: Add Account');
        console.log('2: Generate OTP');
        console.log('3: Remove Account');
        console.log('4: Exit');

        const choice = readlineSync.questionInt('Select an option: ');

        if (choice === 1) {
            addAccount(key);
        } else if (choice === 2) {
            generateOTP(key);
        } else if (choice === 3) {
            removeAccount(key);
        } else if (choice === 4) {
            break;
        } else {
            console.log('Invalid option. Please try again.');
        }
    }
}

main();
