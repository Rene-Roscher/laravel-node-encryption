const { LaravelEncrypter } = require('./src/index.js');

// Generate test key
const testKey = 'base64:' + Buffer.from('12345678901234567890123456789012').toString('base64');

// Set up encrypter
process.env.APP_KEY = testKey;
const encrypter = new LaravelEncrypter();

console.log('🧪 Testing Bidirectional Encryption\n');
console.log('=====================================\n');

// Test cases
const testCases = {
    'simple_string': 'Hello World',
    'empty_string': '',
    'unicode': 'Ümläüte 中文 emoji 🚀',
    'special_chars': '!@#$%^&*()[]{}',
    'integer': 42,
    'float': 3.14159,
    'boolean_true': true,
    'boolean_false': false,
    'null': null,
    'simple_array': [1, 2, 3],
    'assoc_array': { key: 'value', number: 123 },
    'nested': { level1: { level2: { level3: 'deep' } } },
    'mixed': ['string', 123, true, null, { nested: 'array' }]
};

let passed = 0;
let failed = 0;

for (const [name, testData] of Object.entries(testCases)) {
    try {
        // Test encryption and decryption
        const encrypted = encrypter.encrypt(testData);
        const decrypted = encrypter.decrypt(encrypted);

        // Check if decrypted matches original
        const matches = JSON.stringify(decrypted) === JSON.stringify(testData);

        if (matches) {
            console.log(`✅ ${name}: PASSED`);
            passed++;
        } else {
            console.log(`❌ ${name}: FAILED`);
            console.log(`   Expected: ${JSON.stringify(testData)}`);
            console.log(`   Got: ${JSON.stringify(decrypted)}`);
            failed++;
        }
    } catch (error) {
        console.log(`❌ ${name}: ERROR - ${error.message}`);
        failed++;
    }
}

console.log('\n=====================================');
console.log(`📊 Results: ${passed}/${testCases.length} passed, ${failed}/${testCases.length} failed`);
console.log('=====================================');

if (failed > 0) {
    process.exit(1);
}