const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema(
    {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        otp: { type: String },
        otpExpiresAt: { type: Date },
        verified: { type: Boolean, default: false },
        otpGeneratedAt: { type: Date },
        password: { type: String, required: true },
        phone: { type: String, required: true },
        phoneVerification: { type: Boolean, default: false },
        userType: { 
            type: String, 
            required: true, 
            enum: ['Admin', 'Customer', 'GeneralD', 'SubGeneralD', 'DD', 'DH'] 
        },
        profile: {
            type: String,
            required: true,
            default: "https://d326fntlu7tb1e.cloudfront.net/uploads/bdec9d7d-0544-4fc4-823d-3b898f6dbbbf-vinci_03.jpeg"
        },
        companyName: {
            type: String,
            required: [true, 'Company Name is required'],
            trim: true,
            unique: true
        },
        companyPhoneNumber: {
            type: String,
            required: [true, 'Phone Number is required'],
        },
        address: {
            type: String,
            required: [true, 'Address is required'],
        },
        tinNumber: {
            type: String,
            required: [true, 'TIN Number is required'],
            unique: true,
            match: [/^[0-9]{10}$/, 'TIN Number should be 9 digits']
        },
        website: {
            type: String,
            match: [/^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, 'Invalid website URL format'],
            required: false,
        },
        businessType: {
            type: String,
            enum: ['government-ministry', 'private-fintech', 'key-institutions', 'finance-sector', 'others'],
            default: 'others'
        },
        failedAttempts: { type: Number, default: 0 }, 
        lockUntil: { type: Date, default: null },    
    },
    { timestamps: true }
);

module.exports = mongoose.model("User", UserSchema);
