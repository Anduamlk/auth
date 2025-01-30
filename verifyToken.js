const jwt = require("jsonwebtoken");
const User = require("../models/User");


const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(" ")[1];

        jwt.verify(token, process.env.JWT_SEC, async (err, user) => {
            if (err) {
                return res.status(403).json({ status: false, message: "Invalid token" })
            }

            req.user = user;
            next();
        })

    } else {
        return res.status(401).json({ status: false, message: "You are not authenticated" })
    }
}

const verifyTokenAndAuthorization = (req, res, next) => {
    verifyToken(req, res, () => {
        if (
            req.user.userType === 'Customer' ||
            req.user.userType === 'GeneralD' ||
            req.user.userType === 'SubGeneralD' ||
            req.user.userType === 'Admin' ||
            req.user.userType === 'DD' ||
            req.user.userType === 'DH'
        ) {
            next();
        } else {
            res.status(403).json("You are restricted from perfoming this operation");
        }
    });
};

const verifyGeneralD = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "GeneralD" || req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You have limited access");
        }
    });
};


const verifySubGeneralD = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "SubGeneralD" || req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You have limited access Sub");
        }
    });
};



const DD = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "DD" || req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You have limited access");
        }
    });
};

const Customer = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "Customer" || req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You have limited access ");
        }
    });
};
const DH = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "DH" || req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You have limited access");
        }
    });
};




const verifyDirectors = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "GeneralD" || req.user.userType === "Admin" ||  req.user.userType === "SubGeneralD" ||  req.user.userType === "DD") {
            next();
        } else {
            res.status(403).json("You have limited access");
        }
    });
};

 


const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.userType === "Admin") {
            next();
        } else {
            res.status(403).json("You are restricted from perfoming this operation");
        }
    });
};

module.exports = { verifyDirectors, verifyToken, Customer, verifyTokenAndAuthorization, verifySubGeneralD, verifyGeneralD, DH, DD,verifyAdmin };
