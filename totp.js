const crypto = require('crypto');
const fs = require('fs');
const readlineSync = require('readline-sync');
const clipboardy = require('clipboardy');

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

const accountsFile = 'accounts.json';

function loadAccounts() {
    if (!fs.existsSync(accountsFile)) {
        return [];
    }
    const data = fs.readFileSync(accountsFile);
    return JSON.parse(data);
}

function saveAccounts(accounts) {
    fs.writeFileSync(accountsFile, JSON.stringify(accounts, null, 2));
}

function addAccount() {
    const accounts = loadAccounts();
    const accountName = readlineSync.question('Enter account name: ');
    const secret = readlineSync.question('Enter base32 secret: ');

    accounts.push({ name: accountName, secret });
    saveAccounts(accounts);
    console.log('Account saved.');
}

function generateOTP() {
    const accounts = loadAccounts();
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
    while (true) {
        console.log('1: Add Account');
        console.log('2: Generate OTP');
        console.log('3: Exit');

        const choice = readlineSync.questionInt('Select an option: ');

        if (choice === 1) {
            addAccount();
        } else if (choice === 2) {
            generateOTP();
        } else if (choice === 3) {
            break;
        } else {
            console.log('Invalid option. Please try again.');
        }
    }
}

main();
