require('dotenv').config()
const { initializeApp, cert } = require('firebase-admin/app')
const { getFirestore } = require('firebase-admin/firestore')

const serviceAccount = {

    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: process.env.FIREBASE_AUTH_URI,
    token_uri: process.env.FIREBASE_TOKEN_URI,
    auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_x509_CERT_URL,
    client_x509_cert_url: process.env.FIREBASE_CLIENT_x509_CERT_URL,
    universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN

}

initializeApp({
    credential: cert(serviceAccount)
})

const db = getFirestore()

module.exports = { db }
