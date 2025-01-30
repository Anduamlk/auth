const User = require("../../models/User");
const CryptoJS = require("crypto-js");
const crypto = require('crypto');
const jwt = require("jsonwebtoken");
const axios = require('axios');
const generateOtp = require("../../utils/otp_generator");
const sendLoginAlertEmail = require('../../utils/login_alert');
const sendVerificationEmail = require('../../utils/email_verification');
const sendResetPasswordEmail = require('../../utils/reset_pass');

const validateInput = (email, password, confirmPassword, phone, companyPhoneNumber, tinNumber, website) => {
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const phoneRegex = /^(\+251[0-9]{9}|09[0-9]{8})$/;
    const companyPhoneRegex = /^(?:\+251|0)[0-9]{9}$/;  
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
    const tinRegex = /^[0-9]{10}$/; 
    const urlRegex = /^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/?$/;

    if (!emailRegex.test(email)) {
        return { status: false, message: "Invalid email format" };
    }
    
    if (!phoneRegex.test(phone)) {
        return { status: false, message: "Invalid personal phone number format" };
    }
    
    if (!companyPhoneRegex.test(companyPhoneNumber)) {
        return { status: false, message: "Invalid company phone number format" };
    }
    
    if (!tinRegex.test(tinNumber)) {
        return { status: false, message: "Invalid TIN Number. It should be 9 digits" };
    }

    if (!passwordRegex.test(password)) {
        return {
            status: false,
            message: "Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character"
        };
    }

    if (password !== confirmPassword) {
        return { status: false, message: "Passwords do not match" };
    }

    if (website && !urlRegex.test(website)) {
        return { status: false, message: "Invalid website URL format" };
    }

    return { status: true };
};
    
module.exports = {
    
        createUser: async (req, res) => {
            const { 
                firstName, lastName, email, phone, password, confirmPassword,
                companyName, companyPhoneNumber, address, tinNumber, website, businessType 
            } = req.body;
    
            const validationResponse = validateInput(email, password, confirmPassword, phone, companyPhoneNumber, tinNumber, website);
            if (!validationResponse.status) {
                return res.status(400).json(validationResponse);
            }
    
            try {
                const emailExist = await User.findOne({ email });
                if (emailExist) return res.status(400).json({ status: false, message: "Email already exists" });
    
                const companyExist = await User.findOne({ companyName });
                if (companyExist) return res.status(400).json({ status: false, message: "Company Name already exists" });
    
                const tinExist = await User.findOne({ tinNumber });
                if (tinExist) return res.status(400).json({ status: false, message: "TIN Number already exists" });
    

                const otp = generateOtp();
                console.log("Generated OTP:", otp);
    
                const encryptedPassword = CryptoJS.AES.encrypt(password, process.env.SECRET).toString();
    
                const newUser = new User({
                    firstName,
                    lastName,
                    email,
                    phone,
                    password: encryptedPassword,
                    otp,  
                    otpExpiresAt: Date.now() + 10 * 60 * 1000, 
                    userType: "Customer",
                    companyName,
                    companyPhoneNumber,
                    address,
                    tinNumber,
                    website,
                    businessType: businessType || "others",
                });
        
                await newUser.save();

                await sendVerificationEmail(email, otp);
    
                return res.status(200).json({
                    status: true,
                    message: "Account created successfully. A verification code has been sent to your email.",
                });
    
            } catch (error) {
                console.error("Error creating user:", error.message);
                return res.status(500).json({
                    status: false,
                    message: "An error occurred while creating the account. Please try again later.",
                });
            }
        },

        loginUser: async (req, res) => {
            const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
        
            if (!emailRegex.test(req.body.email)) {
                return res.status(400).json({ status: false, message: "Invalid email format" });
            }
        
            const minPasswordLength = 8;
            if (req.body.password.length < minPasswordLength) {
                return res.status(400).json({ status: false, message: `Password should be at least ${minPasswordLength} characters long` });
            }
        
            const MAX_ATTEMPTS = 3; 
            const LOCKOUT_TIME = 15 * 60 * 1000; 
        
            try {
                
                const captchaToken = req.body.captchaToken;
        
                if (!captchaToken) {
                    return res.status(400).json({ status: false, message: "CAPTCHA token is required" });
                }
        
                const captchaResponse = await axios.post(
                    `https://www.google.com/recaptcha/api/siteverify`,
                    null,
                    {
                        params: {
                            secret: process.env.RECAPTCHA_SECRET_KEY, 
                            response: captchaToken, 
                        },
                    }
                );
        
                if (!captchaResponse.data.success) {
                    return res.status(400).json({ status: false, message: "CAPTCHA verification failed. Please try again." });
                }
        
              
                const user = await User.findOne({ email: req.body.email }, { __v: 0, createdAt: 0, updatedAt: 0 });
                if (!user) {
                    return res.status(401).json({ status: false, message: "User not found, check your email address" });
                }
        

                if (user.lockUntil && user.lockUntil > Date.now()) {
                    const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60); // Time in minutes
                    return res.status(403).json({
                        status: false,
                        message: `Account locked. Try again in ${remainingTime} minutes.`,
                    });
                }
        
                const decryptedPassword = CryptoJS.AES.decrypt(user.password, process.env.SECRET).toString(CryptoJS.enc.Utf8);
                if (decryptedPassword !== req.body.password) {
                 
                    user.failedAttempts = (user.failedAttempts || 0) + 1;
        
                    if (user.failedAttempts >= MAX_ATTEMPTS) {
                        user.lockUntil = Date.now() + LOCKOUT_TIME; 
                        await user.save();
                        return res.status(403).json({
                            status: false,
                            message: `Too many failed attempts. Account locked for ${LOCKOUT_TIME / 60000} minutes.`,
                        });
                    }
        
                    await user.save(); 
                    return res.status(401).json({ status: false, message: "Wrong password" });
                }
                user.failedAttempts = 0;
                user.lockUntil = null;
                await user.save();
        
                const userToken = jwt.sign(
                    {
                        id: user._id,
                        userType: user.userType,
                        email: user.email,
                    },
                    process.env.JWT_SEC,
                    { expiresIn: "21d" }
                );
        
                await sendLoginAlertEmail.sendLoginAlertEmail(user.email, req.ip, req.headers["user-agent"]);
                const { password, otp, ...others } = user._doc;
        
                return res.status(200).json({ ...others, userToken, message: "Login successful" });
            } catch (error) {
                console.error("Error during login:", error.message);
                return res.status(500).json({ status: false, message: "Server error. Please try again later." });
            }
        },
        
        

    forgotPassword: async (req, res) => {
        const { email } = req.body;
    
        if (!email) {
            return res.status(400).json({ status: false, message: "Email is required" });
        }
    
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return res.status(404).json({ status: false, message: "User not found" });
            }
    
            // Generate a JWT reset token (valid for 1 hour)
            const resetToken = jwt.sign(
                { id: user._id },
                process.env.JWT_SEC,  // Use the same secret as the normal login
                { expiresIn: '1h' }
            );
    
            // Save the reset token in the user document (optional)
            user.resetPasswordToken = resetToken;
            user.resetPasswordExpires = Date.now() + 3600000; // 1 hour expiration
            await user.save();
    
            // Send the reset link with the token
            const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
            await sendResetPasswordEmail(user.email, resetLink);
    
            return res.status(200).json({
                status: true,
                message: "Password recovery email sent successfully. Please check your inbox.",
            });
    
        } catch (error) {
            console.error('Error during forgot password:', error.message);
            return res.status(500).json({ status: false, message: "Server error. Please try again later." });
        }
    },
    
    resetPassword: async (req, res) => {
        const { token, newPassword } = req.body;
    
        if (!token || !newPassword) {
            return res.status(400).json({ status: false, message: "Token and new password are required" });
        }
    
        try {
            let decoded;
            try {
                decoded = jwt.verify(token, process.env.JWT_SEC);  
            } catch (err) {
                console.error('JWT verification error:', err.message);
                return res.status(400).json({ status: false, message: 'Invalid or expired token' });
            }
    
            const user = await User.findById(decoded.id);
            if (!user) {
                return res.status(404).json({ status: false, message: 'User not found' });
            }
            const minPasswordLength = 8;
            if (newPassword.length < minPasswordLength) {
                return res.status(400).json({ status: false, message: `Password should be at least ${minPasswordLength} characters long` });
            }
    
            const encryptedPassword = CryptoJS.AES.encrypt(newPassword, process.env.SECRET).toString();
    
            user.password = encryptedPassword;
            await user.save();
    
            return res.status(200).json({ status: true, message: 'Password reset successful' });
        } catch (error) {
            console.error('Error resetting password:', error.message);
            return res.status(500).json({ status: false, message: "Server error." });
        }
    },
    
    verifyOtp: async (req, res) => {
        const { otp } = req.body;  
    
        if (!otp) {
            return res.status(400).json({ status: false, message: "OTP is required." });
        }
    
        try {
           
            const user = await User.findOne({ otp });
    
            if (!user) {
                return res.status(404).json({ status: false, message: "User not found with this OTP." });
            }
    
            if (user.otp !== otp) {
                return res.status(400).json({ status: false, message: "Invalid OTP." });
            }
            if (user.otpExpiresAt < Date.now()) {
                return res.status(400).json({ status: false, message: "OTP has expired." });
            }
            user.verified = true;
            user.otp = undefined;  
            user.otpExpiresAt = undefined;  
            await user.save();

            return res.status(200).json({ status: true, message: "OTP verified successfully." });
    
        } catch (error) {
            console.error("Error verifying OTP:", error.message);
            return res.status(500).json({ status: false, message: "An error occurred. Please try again later." });
        }
    }
 

};
