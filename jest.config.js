module.exports = {
    testEnvironment: 'node',
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/**/*.test.js',
        '!src/**/*.spec.js'
    ],
    coverageDirectory: 'coverage',
    coverageThreshold: {
        global: { statements: 95, branches: 90, functions: 95, lines: 95 }
    },
    coverageReporters: ['text', 'lcov', 'html'],
    testMatch: [
        '**/test/**/*.test.js',
        '**/test/**/*.spec.js'
    ],
    verbose: true
};