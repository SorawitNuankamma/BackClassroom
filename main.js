var $3ezkb$mongoose = require("mongoose");
var $3ezkb$dotenv = require("dotenv");
var $3ezkb$express = require("express");
var $3ezkb$morgan = require("morgan");
var $3ezkb$expressratelimit = require("express-rate-limit");
var $3ezkb$helmet = require("helmet");
var $3ezkb$expressmongosanitize = require("express-mongo-sanitize");
var $3ezkb$xssclean = require("xss-clean");
var $3ezkb$hpp = require("hpp");
var $3ezkb$compression = require("compression");
var $3ezkb$cors = require("cors");
var $3ezkb$validator = require("validator");
var $3ezkb$bcryptjs = require("bcryptjs");
var $3ezkb$crypto = require("crypto");
var $3ezkb$nodefetch = require("node-fetch");
var $3ezkb$jsonwebtoken = require("jsonwebtoken");
var $3ezkb$util = require("util");
var $3ezkb$nodemailer = require("nodemailer");
var $3ezkb$linebotsdk = require("@line/bot-sdk");



process.on('uncaughtException', (err)=>{
    console.log('UNCAUGHT REJECTION !!! SHUTTING DOWN');
    console.log(err.name, err.message);
    process.exit(1);
});
$3ezkb$dotenv.config({
    path: './config.env'
});
var $7d1ce68b22eaf435$exports = {};
var $9cb55335762babe3$exports = {};
class $9cb55335762babe3$var$AppError extends Error {
    constructor(message, statusCode){
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
$9cb55335762babe3$exports = $9cb55335762babe3$var$AppError;


var $3c8c1d1e096e9f2d$exports = {};

const $3c8c1d1e096e9f2d$var$handleJWTExpiredError = ()=>new $9cb55335762babe3$exports('your token has expire, please login again', 401)
;
const $3c8c1d1e096e9f2d$var$handleJWTError = ()=>new $9cb55335762babe3$exports('Invalid token, please login again', 401)
;
const $3c8c1d1e096e9f2d$var$handleDuplicateFieldsDB = (err)=>{
    const message = `Duplicate value`;
    let error = new $9cb55335762babe3$exports(message, 400);
    return error;
};
const $3c8c1d1e096e9f2d$var$handleCastErrorDB = (err)=>{
    const message = `Invalid ${err.path}: ${err.value}`;
    let error = new $9cb55335762babe3$exports(message, 400);
    return error;
};
const $3c8c1d1e096e9f2d$var$handleValidationErrorDB = (err)=>{
    const errors = Object.values(err.errors).map((el)=>el.message
    );
    const message = `Invalid data input ${errors.join(', ')}`;
    let error = new $9cb55335762babe3$exports(message, 400);
    return error;
};
const $3c8c1d1e096e9f2d$var$sendErrorDev = (err, res)=>{
    res.status(err.statusCode).json({
        status: err.status,
        error: err,
        message: err.message,
        stack: err.stack
    });
};
const $3c8c1d1e096e9f2d$var$sendErrorProd = (err, res)=>{
    // Operational Error
    if (err.isOperational) res.status(err.statusCode).json({
        status: err.status,
        message: err.message
    });
    else // send error message
    res.status(500).json({
        status: 'error',
        stack: 'Something went wrong'
    });
};
$3c8c1d1e096e9f2d$exports = (err, req, res, next)=>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';
    if (process.env.NODE_ENV === 'development') $3c8c1d1e096e9f2d$var$sendErrorDev(err, res);
    else if (process.env.NODE_ENV === 'production') {
        let error = {
            ...err
        };
        //console.log(err);
        if (err.name == 'CastError') error = $3c8c1d1e096e9f2d$var$handleCastErrorDB(error);
        if (err.code == 11000) error = $3c8c1d1e096e9f2d$var$handleDuplicateFieldsDB(error);
        if (err.name == 'ValidationError') error = $3c8c1d1e096e9f2d$var$handleValidationErrorDB(error);
        if (err.name == 'JsonWebTokenError') error = $3c8c1d1e096e9f2d$var$handleJWTError();
        if (err.name == 'TokenExpiredError') error = $3c8c1d1e096e9f2d$var$handleJWTExpiredError();
        $3c8c1d1e096e9f2d$var$sendErrorProd(error, res);
    }
};











var $3e835eff6fbf8a5e$exports = {};

// Adminstator API
//ROUTE HANDLER
var $b0c4ba1e82d2fcde$export$69093b9c569a5b5b;
var $b0c4ba1e82d2fcde$export$7cbf767827cd68ba;
var $b0c4ba1e82d2fcde$export$402fbb8c0ae400db;
var $b0c4ba1e82d2fcde$export$e3ac7a5d19605772;
var $b0c4ba1e82d2fcde$export$7d0f10f273c0438a;
var $b0c4ba1e82d2fcde$export$59f3ba6b40e64e77;
// User public API
var $b0c4ba1e82d2fcde$export$46d0484665757df5;
// User route
var $b0c4ba1e82d2fcde$export$8ebc4b9f4a31a32;
var $75e0ea661a1be51e$exports = {};




const $75e0ea661a1be51e$var$userSchema = new $3ezkb$mongoose.Schema({
    name: {
        type: String,
        default: 'default_user_name',
        maxlength: [
            20,
            'a name should not be longer than 10 character'
        ],
        minlength: [
            3,
            'a name must be longer than 3 character'
        ],
        validator: [
            $3ezkb$validator.isAlpha,
            'must only contain character'
        ]
    },
    lineID: {
        type: String
    },
    email: {
        type: String,
        unique: true,
        validate: [
            $3ezkb$validator.isEmail,
            'must be an valid email'
        ]
    },
    role: {
        type: String,
        enum: [
            'user',
            'admin'
        ],
        default: 'user'
    },
    photo: String,
    password: {
        type: String,
        require: [
            true,
            'Password is require'
        ],
        minlength: [
            8,
            'a password must be longer than 8 character'
        ],
        select: false
    },
    passwordChangedAt: Date,
    classrooms: {
        type: Array,
        default: []
    },
    passwordResetToken: String,
    passwordResetExpire: Date
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
/*
userSchema.virtual('virtualNumber').get(function () {
  return this.number * 2;
});
*/ // Document Middleware for hashing password
$75e0ea661a1be51e$var$userSchema.pre('save', async function(next) {
    // only run if passwod are modify
    if (!this.isModified('password')) return next();
    this.password = await $3ezkb$bcryptjs.hash(this.password, 12);
    next();
});
// method คือ function ที่ call ได้ทุกที่กับ object นี้
$75e0ea661a1be51e$var$userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
    return await $3ezkb$bcryptjs.compare(candidatePassword, userPassword);
};
$75e0ea661a1be51e$var$userSchema.methods.changedPasswordAfter = function(JWTTimeStamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimeStamp < changedTimestamp;
    }
    return false;
};
// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
$75e0ea661a1be51e$var$userSchema.pre('save', function(next) {
    if (!this.isModified('password') || this.isNew) return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
});
$75e0ea661a1be51e$var$userSchema.methods.createPasswordResetToken = function() {
    const resetToken = $3ezkb$crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = $3ezkb$crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpire = Date.now() + 600000;
    //console.log({ resetToken }, this.passwordResetToken);
    return resetToken;
};
const $75e0ea661a1be51e$var$User = $3ezkb$mongoose.model('User', $75e0ea661a1be51e$var$userSchema);
$75e0ea661a1be51e$exports = $75e0ea661a1be51e$var$User;


var $6c281682e6431d39$exports = {};
class $6c281682e6431d39$var$APIFeatures {
    filter() {
        // 1A filtering
        const queryObj = {
            ...this.queryString
        }; // create new query object
        const excludeFields = [
            'page',
            'sort',
            'limit',
            'fields'
        ]; // list of unquery word
        excludeFields.forEach((el)=>delete queryObj[el]
        ); // get query  from database
        // 1B advance filtering
        let queryStr = JSON.stringify(queryObj); // แปลง queryObj เป็น string
        queryStr = queryStr.replace(/\b(gte|gt|lt|lte)\b/g, (match)=>`$${match}`
        ); // replace string เป็น queryObject
        this.query = this.query.find(JSON.parse(queryStr));
        return this;
    }
    sort() {
        if (this.queryString.sort) {
            const sortBy = this.queryString.sort.split(',').join(' ');
            this.query = this.query.sort(sortBy);
        } else this.query = this.query.sort('name');
        return this;
    }
    limitFields() {
        if (this.queryString.fields) {
            const fields = this.queryString.fields.split(',').join(' ');
            this.query = this.query.select(fields);
        } else this.query = this.query.select('-__v');
        return this;
    }
    paginate() {
        const page = this.queryString.page * 1 || 1;
        const limit = this.queryString.limit * 1 || 100;
        const skip = (page - 1) * limit;
        this.query = this.query.skip(skip).limit(limit);
        return this;
    }
    constructor(query, queryString){
        this.query = query;
        this.queryString = queryString;
    }
}
$6c281682e6431d39$exports = $6c281682e6431d39$var$APIFeatures;



var $16c36c10cc7e291e$exports = {};
$16c36c10cc7e291e$exports = (fn)=>{
    return (req, res, next)=>{
        fn(req, res, next).catch(next);
    };
};


/**
 * Filter an object by passing in an array of allowed fields.
 */ var $aa33edf437096a90$export$1039dc7987464938;
$aa33edf437096a90$export$1039dc7987464938 = (obj, ...allowedFields)=>{
    const newObj = {
    };
    Object.keys(obj).forEach((el)=>{
        if (allowedFields.includes(el)) newObj[el] = obj[el];
    });
    return newObj;
};


$b0c4ba1e82d2fcde$export$69093b9c569a5b5b = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $6c281682e6431d39$exports($75e0ea661a1be51e$exports.find(), req.query).filter().sort().limitFields().paginate();
    const users = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            users: users
        }
    });
});
$b0c4ba1e82d2fcde$export$7cbf767827cd68ba = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $75e0ea661a1be51e$exports.findById(req.params.id);
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$b0c4ba1e82d2fcde$export$402fbb8c0ae400db = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newUser = await $75e0ea661a1be51e$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newUser: newUser
        }
    });
});
$b0c4ba1e82d2fcde$export$e3ac7a5d19605772 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $75e0ea661a1be51e$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$b0c4ba1e82d2fcde$export$7d0f10f273c0438a = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $75e0ea661a1be51e$exports.findByIdAndDelete(req.params.id);
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$b0c4ba1e82d2fcde$export$59f3ba6b40e64e77 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const stats = await $75e0ea661a1be51e$exports.aggregate([
        {
            $match: {
                number: {
                    $gte: 3
                }
            }
        },
        {
            $group: {
                _id: '$email',
                num: {
                    $sum: 1
                },
                sumNum: {
                    $sum: '$number'
                },
                avg: {
                    $avg: '$number'
                },
                min: {
                    $min: '$number'
                },
                max: {
                    $max: '$number'
                }
            }
        },
        {
            $sort: {
                avg: 1
            }
        },
        {
            $match: {
                _id: {
                    $ne: 'sorawit.nu@ku.th'
                }
            }
        }, 
    ]);
    res.status(200).json({
        status: 'success',
        data: {
            stats: stats
        }
    });
});
$b0c4ba1e82d2fcde$export$46d0484665757df5 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check condition
    if (req.body.password) return next(new $9cb55335762babe3$exports('cannot change password on this route', 400));
    //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
    const filterdBody = $aa33edf437096a90$export$1039dc7987464938(req.body, 'name');
    const updateUser = await $75e0ea661a1be51e$exports.findByIdAndUpdate(req.user.id, filterdBody, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            user: updateUser
        }
    });
});
$b0c4ba1e82d2fcde$export$8ebc4b9f4a31a32 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = req.user;
    if (!user) return next(new $9cb55335762babe3$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});


var $0bc8f3793ef000ed$export$7200a869094fec36;
var $0bc8f3793ef000ed$export$596d806903d1f59e;
//Middleware function for protect route
var $0bc8f3793ef000ed$export$eda7ca9e36571553;
var $0bc8f3793ef000ed$export$e1bac762c84d3b0c;
var $0bc8f3793ef000ed$export$37ac0238687b67ae;
var $0bc8f3793ef000ed$export$dc726c8e334dd814;
var $0bc8f3793ef000ed$export$e2853351e15b7895;
var $0bc8f3793ef000ed$export$e8ba96907705e541;
var $0bc8f3793ef000ed$export$199b5f9b35e82fdc;
var $0bc8f3793ef000ed$export$533fea6504b9ca2e;
//Middleware function for protect route
var $0bc8f3793ef000ed$export$fb0dc8052b1814d7;



var $fd22212e3c25cb5a$exports = {};




const $fd22212e3c25cb5a$var$lineUserSchema = new $3ezkb$mongoose.Schema({
    name: {
        type: String,
        default: 'default_user_name',
        maxlength: [
            20,
            'a name should not be longer than 10 character'
        ],
        minlength: [
            3,
            'a name must be longer than 3 character'
        ],
        validator: [
            $3ezkb$validator.isAlpha,
            'must only contain character'
        ]
    },
    lineUserId: {
        type: String,
        unique: true
    },
    email: {
        type: String
    },
    role: {
        type: String,
        enum: [
            'user',
            'admin'
        ],
        default: 'user'
    },
    pictureURL: String,
    classrooms: {
        type: Array,
        default: []
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
const $fd22212e3c25cb5a$var$LineUser = $3ezkb$mongoose.model('LineUser', $fd22212e3c25cb5a$var$lineUserSchema);
$fd22212e3c25cb5a$exports = $fd22212e3c25cb5a$var$LineUser;




var $1cd4445fcdef0ad5$exports = {};

const $1cd4445fcdef0ad5$var$sendEmail = async (options)=>{
    // Create a transporter
    const transporter = $3ezkb$nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD
        }
    });
    // Define the email option
    const mailOptions = {
        from: 'Sorawit Nuankamma <sorawit@smartclassroom.io>',
        to: options.email,
        subject: options.subject,
        text: options.message
    };
    // Actually send the email
    await transporter.sendMail(mailOptions);
};
$1cd4445fcdef0ad5$exports = $1cd4445fcdef0ad5$var$sendEmail;




var $0bc8f3793ef000ed$require$promisify = $3ezkb$util.promisify;
const $0bc8f3793ef000ed$var$verifyLineToken = async (token)=>{
    const response = await $3ezkb$nodefetch(`https://api.line.me/oauth2/v2.1/verify?access_token=${token}`, {
        method: 'GET',
        mode: 'cors'
    });
    return response.json(); // parses JSON response into native JavaScript objects
};
const $0bc8f3793ef000ed$var$getLineUserProfile = async (token)=>{
    const response = await $3ezkb$nodefetch(`https://api.line.me/v2/profile`, {
        method: 'GET',
        mode: 'cors',
        headers: {
            Authorization: 'Bearer ' + token
        }
    });
    return response.json(); // parses JSON response into native JavaScript objects
};
const $0bc8f3793ef000ed$var$signToken = (id)=>{
    return $3ezkb$jsonwebtoken.sign({
        id: id
    }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};
const $0bc8f3793ef000ed$var$createSendToken = (user, statusCode, res)=>{
    const token = $0bc8f3793ef000ed$var$signToken(user._id);
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 86400000),
        httpOnly: true
    };
    process.env.NODE_ENV = 'production';
    cookieOptions.secure = true;
    res.cookie('jwt', token, cookieOptions);
    // remove the password
    user.password = undefined;
    res.status(statusCode).json({
        status: 'success',
        token: token,
        data: {
            user: user
        }
    });
};
$0bc8f3793ef000ed$export$7200a869094fec36 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newUser = await $75e0ea661a1be51e$exports.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        lineID: req.body.lineID
    });
    $0bc8f3793ef000ed$var$createSendToken(newUser, 201, res);
});
$0bc8f3793ef000ed$export$596d806903d1f59e = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const { email: email , password: password  } = req.body;
    // check if email and password is exist
    if (!email || !password) return next(new $9cb55335762babe3$exports('Please provide user and password', 400));
    // check if user exist and password correct
    const user = await $75e0ea661a1be51e$exports.findOne({
        email: email
    }).select('+password');
    if (!user || !await user.correctPassword(password, user.password)) return next(new $9cb55335762babe3$exports('Incorrect email or password', 401));
    $0bc8f3793ef000ed$var$createSendToken(user, 200, res);
});
$0bc8f3793ef000ed$export$eda7ca9e36571553 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    //console.log(token);
    if (!token) return next(new $9cb55335762babe3$exports('You are not logged in!', 401));
    // verification the token
    const decoded = await $0bc8f3793ef000ed$require$promisify($3ezkb$jsonwebtoken.verify)(token, process.env.JWT_SECRET);
    // check if user still exist
    const currentUser = await $75e0ea661a1be51e$exports.findById(decoded.id);
    if (!currentUser) return next(new $9cb55335762babe3$exports('the token belong to this user is no longer exist', 401));
    // check if user changed password after the token was issue
    if (currentUser.changedPasswordAfter(decoded.iat)) return next(new $9cb55335762babe3$exports('user password has been change, please login again', 401));
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});
$0bc8f3793ef000ed$export$e1bac762c84d3b0c = (...roles)=>{
    return (req, res, next)=>{
        // role [ user, admin]
        if (!roles.includes(req.user.role)) return next(new $9cb55335762babe3$exports('you do not have permission', 403));
        next();
    };
};
$0bc8f3793ef000ed$export$37ac0238687b67ae = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // get user base on email
    const user = await $75e0ea661a1be51e$exports.findOne({
        email: req.body.email
    });
    if (!user) return next(new $9cb55335762babe3$exports('no user with that email', 404));
    // generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({
        validateBeforeSave: false
    });
    // send it to user email
    const resetURL = `${req.protocol}://${req.get('host')}/api/users/resetPassword/${resetToken}`;
    const message = `submit the patch request to change you password to ${resetURL}`;
    try {
        await $1cd4445fcdef0ad5$exports({
            email: user.email,
            subject: 'You password reset token (valid for 10min)',
            message: message
        });
        res.status(200).json({
            status: 'success',
            message: 'token send to email'
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpire = undefined;
        await user.save({
            validateBeforeSave: false
        });
        return next(new $9cb55335762babe3$exports('There was an error sending an email, try again later', 500));
    }
});
$0bc8f3793ef000ed$export$dc726c8e334dd814 = async (req, res, next)=>{
    // get user base on the token
    const hashedToken = $3ezkb$crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await $75e0ea661a1be51e$exports.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpire: {
            $gt: Date.now()
        }
    });
    // if token has not expire, and there is a user, set the new password
    if (!user) return next(new $9cb55335762babe3$exports('Token is invalid or has expired', 400));
    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    await user.save();
    // update changedPasswordAt property for the user
    // log the user in and send JWT
    $0bc8f3793ef000ed$var$createSendToken(user, 200, res);
};
$0bc8f3793ef000ed$export$e2853351e15b7895 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // get user
    let user = req.user;
    user = await $75e0ea661a1be51e$exports.findById(req.user.id).select('+password');
    // check that current password that user provide is correct
    if (!user || !await user.correctPassword(req.body.password, user.password)) return next(new $9cb55335762babe3$exports('Incorrect email or password', 401));
    // update the password
    user.password = req.body.newPassword;
    await user.save();
    // update changedPasswordAt property for the user
    // log the user in and send JWT
    $0bc8f3793ef000ed$var$createSendToken(user, 200, res);
});
$0bc8f3793ef000ed$export$e8ba96907705e541 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // SEND RESPONSE
    res.status(200).json({
        status: 'success'
    });
});
$0bc8f3793ef000ed$export$199b5f9b35e82fdc = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    if (!token) return next(new $9cb55335762babe3$exports('You are not provide a token!', 401));
    //DEVELOPMENT ONLY
    if (token === process.env.BYPASS_TOKEN) $fd22212e3c25cb5a$exports.findOne({
        lineUserId: 'FAKELINEUSERID'
    }).then((lineUser)=>{
        if (!lineUser) return next(new $9cb55335762babe3$exports('user not found', 401));
        $0bc8f3793ef000ed$var$createSendToken(lineUser, 200, res);
    });
    if (token === process.env.BYPASS_TOKEN2) $fd22212e3c25cb5a$exports.findOne({
        lineUserId: 'a1s0andf7us3r'
    }).then((lineUser)=>{
        if (!lineUser) return next(new $9cb55335762babe3$exports('user not found', 401));
        $0bc8f3793ef000ed$var$createSendToken(lineUser, 200, res);
    });
    //DEVELOPMENT ONLY END
    // verification the token
    // somehow can't figure out this to working with  await
    $0bc8f3793ef000ed$var$verifyLineToken(token).then((verifyResult)=>{
        if (!verifyResult.client_id) return next(new $9cb55335762babe3$exports('Invalid token or token are no longer valid', 401));
        //Use line token to get user information
        $0bc8f3793ef000ed$var$getLineUserProfile(token).then((userProfile)=>{
            // check if line user already exist
            const lineUserId = userProfile.userId;
            $fd22212e3c25cb5a$exports.findOne({
                lineUserId: lineUserId
            }).then((lineUser)=>{
                if (!lineUser) return next(new $9cb55335762babe3$exports('user not found', 401));
                $0bc8f3793ef000ed$var$createSendToken(lineUser, 200, res);
            });
        });
    });
});
$0bc8f3793ef000ed$export$533fea6504b9ca2e = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    if (!token) return next(new $9cb55335762babe3$exports('You are not provide a token!', 401));
    // verification the token
    // somehow can't figure out this to working with  await
    $0bc8f3793ef000ed$var$verifyLineToken(token).then((verifyResult)=>{
        if (!verifyResult.client_id) return next(new $9cb55335762babe3$exports('Invalid token or token are no longer valid', 401));
        //Use line token to get use information
        $0bc8f3793ef000ed$var$getLineUserProfile(token).then((userProfile)=>{
            // save user profile in lineUser
            console.log(userProfile);
            $fd22212e3c25cb5a$exports.create({
                name: userProfile.displayName,
                lineUserId: userProfile.userId,
                pictureURL: userProfile.pictureUrl
            }).then((newLineUser)=>{
                $0bc8f3793ef000ed$var$createSendToken(newLineUser, 200, res);
            }).catch((err)=>{
                res.status(500).json({
                    status: 'fail',
                    error: err
                });
            });
        });
    });
});
$0bc8f3793ef000ed$export$fb0dc8052b1814d7 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    //console.log(token);
    if (!token) return next(new $9cb55335762babe3$exports('You are not logged in!', 401));
    // verification the token
    const decoded = await $0bc8f3793ef000ed$require$promisify($3ezkb$jsonwebtoken.verify)(token, process.env.JWT_SECRET);
    // check if user still exist
    const currentUser = await $fd22212e3c25cb5a$exports.findById(decoded.id);
    if (!currentUser) return next(new $9cb55335762babe3$exports('the token belong to this user is no longer exist', 401));
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});


// create router from express
const $3e835eff6fbf8a5e$var$router = $3ezkb$express.Router();
// Normal route
$3e835eff6fbf8a5e$var$router.get('/getMyUser', $0bc8f3793ef000ed$export$eda7ca9e36571553, $b0c4ba1e82d2fcde$export$8ebc4b9f4a31a32);
$3e835eff6fbf8a5e$var$router.post('/signup', $0bc8f3793ef000ed$export$7200a869094fec36);
$3e835eff6fbf8a5e$var$router.post('/login', $0bc8f3793ef000ed$export$596d806903d1f59e);
$3e835eff6fbf8a5e$var$router.post('/isLogin', $0bc8f3793ef000ed$export$eda7ca9e36571553, $0bc8f3793ef000ed$export$e8ba96907705e541);
$3e835eff6fbf8a5e$var$router.post('/forgetPassword', $0bc8f3793ef000ed$export$37ac0238687b67ae);
$3e835eff6fbf8a5e$var$router.patch('/resetPassword/:token', $0bc8f3793ef000ed$export$dc726c8e334dd814);
$3e835eff6fbf8a5e$var$router.patch('/updatePassword', $0bc8f3793ef000ed$export$eda7ca9e36571553, $0bc8f3793ef000ed$export$e2853351e15b7895);
$3e835eff6fbf8a5e$var$router.patch('/updateMyUser', $0bc8f3793ef000ed$export$eda7ca9e36571553, $b0c4ba1e82d2fcde$export$46d0484665757df5);
// Aggreatte route
$3e835eff6fbf8a5e$var$router.route('/users-stats').get($b0c4ba1e82d2fcde$export$59f3ba6b40e64e77);
// CRUD Route  Authentication | Authorization | Responce
$3e835eff6fbf8a5e$var$router.route('/').get($0bc8f3793ef000ed$export$eda7ca9e36571553, $b0c4ba1e82d2fcde$export$69093b9c569a5b5b).post($b0c4ba1e82d2fcde$export$402fbb8c0ae400db);
$3e835eff6fbf8a5e$var$router.route('/:id').get($b0c4ba1e82d2fcde$export$7cbf767827cd68ba).patch($b0c4ba1e82d2fcde$export$e3ac7a5d19605772).delete($0bc8f3793ef000ed$export$eda7ca9e36571553, $0bc8f3793ef000ed$export$e1bac762c84d3b0c('admin'), $b0c4ba1e82d2fcde$export$7d0f10f273c0438a);
$3e835eff6fbf8a5e$exports = $3e835eff6fbf8a5e$var$router;


var $288c55e739a4086a$exports = {};

var $21c44091d380f68a$export$d444b7d547b9817;
// Adminstator API
//ROUTE HANDLER
var $21c44091d380f68a$export$163431112299797c;
var $21c44091d380f68a$export$73c5e4cf93b51e2e;
var $21c44091d380f68a$export$da844db56365444b;
var $21c44091d380f68a$export$d307a271b3ff1f0e;
var $21c44091d380f68a$export$68c77c1b6fffcad5;
// Classroom public API
var $21c44091d380f68a$export$722dc050e19ae38;
// Classroom route
var $21c44091d380f68a$export$8d9158a33355848;
var $21c44091d380f68a$export$e3605f144727d735;
//
var $21c44091d380f68a$export$f506e914f8dedfdc;
// Classroom route
var $21c44091d380f68a$export$631f9d278801ba4;
// Classroom route
var $21c44091d380f68a$export$774968d3a7e3c13d;
var $125027fea43c067a$exports = {};






const $125027fea43c067a$var$classroomSchema = new $3ezkb$mongoose.Schema({
    name: {
        type: String,
        default: 'default_classname_name',
        maxlength: [
            50,
            'a name should not be longer than 30 character'
        ],
        minlength: [
            5,
            'a name must be longer than 3 character'
        ],
        validator: [
            $3ezkb$validator.isAlpha,
            'must only contain character'
        ]
    },
    description: {
        type: String
    },
    color: {
        type: String,
        enum: [
            'red',
            'green',
            'blue',
            'yellow'
        ],
        default: 'green'
    },
    users: Array,
    accessCode: {
        type: String,
        unique: true
    },
    rules: String,
    grader: Array,
    calender: Array,
    timetable: Array,
    lineGroupChatId: String,
    classroomChangedAt: Date
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// Generate accessCode on new
$125027fea43c067a$var$classroomSchema.pre('save', function(next) {
    if (!this.isNew) return next();
    // Generate Room Code
    this.accessCode = $3ezkb$crypto.randomBytes(3).toString('hex');
    next();
});
// Cascade Save
$125027fea43c067a$var$classroomSchema.post('save', async function(doc) {
    const user = await $fd22212e3c25cb5a$exports.findById(doc.users[0].userId);
    user.classrooms.push({
        classroomId: doc.id,
        classroomName: doc.name,
        classroomColor: doc.color,
        classroomRole: doc.users[0].classroomRole
    });
    await user.save();
});
// Cascade Delete
$125027fea43c067a$var$classroomSchema.post('findOneAndDelete', async function(doc) {
    const user = await $fd22212e3c25cb5a$exports.findById(doc.users[0].userId);
    user.classrooms = user.classrooms.filter((el)=>doc.id !== el.classroomId
    );
    await user.save();
});
const $125027fea43c067a$var$Classroom = $3ezkb$mongoose.model('Classroom', $125027fea43c067a$var$classroomSchema);
$125027fea43c067a$exports = $125027fea43c067a$var$Classroom;



var $a9dc971d056127bf$exports = {};



const $a9dc971d056127bf$var$client = new $3ezkb$linebotsdk.Client({
    channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN
});
const $a9dc971d056127bf$var$contentSchema = new $3ezkb$mongoose.Schema({
    title: {
        type: String,
        default: 'default_content_name',
        maxlength: [
            20,
            'a name should not be longer than 10 character'
        ],
        minlength: [
            3,
            'a name must be longer than 3 character'
        ],
        validator: [
            $3ezkb$validator.isAlpha,
            'must only contain character'
        ]
    },
    writers: {
        type: Array
    },
    type: {
        type: String,
        enum: [
            'annoucement',
            'lesson',
            'assignment',
            'none'
        ],
        default: 'none'
    },
    body: Object,
    classId: String,
    createDate: String,
    lastChangeDate: String,
    dueDate: String
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
$a9dc971d056127bf$var$contentSchema.pre('save', function(next) {
    this.createDate = Date();
    next();
});
const $a9dc971d056127bf$var$Content = $3ezkb$mongoose.model('Content', $a9dc971d056127bf$var$contentSchema);
$a9dc971d056127bf$exports = $a9dc971d056127bf$var$Content;


var $850feb170637aab1$exports = {};


const $850feb170637aab1$var$submissionSchema = new $3ezkb$mongoose.Schema({
    comment: {
        type: String,
        default: '',
        maxlength: [
            100,
            'a name should not be longer than 10 character'
        ]
    },
    score: {
        type: Number,
        default: 0,
        min: [
            0,
            'must be more than 0'
        ],
        max: [
            100,
            'must be less or equal to 100'
        ]
    },
    userId: String,
    contentId: String,
    classroomId: String,
    submitDate: String,
    isStudent: Boolean,
    isGraded: {
        type: Boolean,
        default: false
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// Save Date on every save
$850feb170637aab1$var$submissionSchema.pre('save', function(next) {
    this.submitDate = Date();
    next();
});
const $850feb170637aab1$var$Submission = $3ezkb$mongoose.model('Submission', $850feb170637aab1$var$submissionSchema);
$850feb170637aab1$exports = $850feb170637aab1$var$Submission;






$21c44091d380f68a$export$d444b7d547b9817 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    //Validate data
    //packing data
    const classroomObject = {
        name: req.body.name,
        description: req.body.description,
        color: req.body.color,
        users: [],
        rules: req.body.rules,
        grader: [],
        calender: [],
        timetable: {
            mon: [],
            tue: [],
            wed: [],
            thu: [],
            fri: [],
            sat: [],
            sun: []
        }
    };
    // fill grader
    // fill timetable
    req.body.timetable.forEach((el)=>{
        let day = el[0];
        switch(day){
            case 'Monday':
                classroomObject.timetable.mon.push(el[1]);
                break;
            case 'Tuesday':
                classroomObject.timetable.tue.push(el[1]);
                break;
            case 'Wednesday':
                classroomObject.timetable.wed.push(el[1]);
                break;
            case 'Thursday':
                classroomObject.timetable.thu.push(el[1]);
                break;
            case 'Friday':
                classroomObject.timetable.fri.push(el[1]);
                break;
            case 'Saturday':
                classroomObject.timetable.sat.push(el[1]);
                break;
            case 'Sunday':
                classroomObject.timetable.sun.push(el[1]);
                break;
            default:
                break;
        }
    });
    classroomObject.users.push({
        userId: req.user.id,
        name: req.user.name,
        classroomRole: 'Owner'
    });
    req.body = classroomObject;
    next();
});
$21c44091d380f68a$export$163431112299797c = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    //console.log(query);
    // TODO : Fix query
    const features = new $6c281682e6431d39$exports($125027fea43c067a$exports.find(), req.query).filter().sort().limitFields().paginate();
    const classrooms = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            classrooms: classrooms
        }
    });
});
$21c44091d380f68a$export$73c5e4cf93b51e2e = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const classroom = await $125027fea43c067a$exports.findById(req.params.id);
    if (!classroom) return next(new $9cb55335762babe3$exports('no Classroom found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            classroom: classroom
        }
    });
});
$21c44091d380f68a$export$da844db56365444b = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newClassroom = await $125027fea43c067a$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newClassroom: newClassroom
        }
    });
});
$21c44091d380f68a$export$d307a271b3ff1f0e = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const classroom = await $125027fea43c067a$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!classroom) return next(new $9cb55335762babe3$exports('no Classroom found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            classroom: classroom
        }
    });
});
$21c44091d380f68a$export$68c77c1b6fffcad5 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const classroom = await $125027fea43c067a$exports.findByIdAndDelete(req.params.id);
    if (!classroom) return next(new $9cb55335762babe3$exports('no Classroom found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$21c44091d380f68a$export$722dc050e19ae38 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check condition
    if (req.body.accessCode) return next(new $9cb55335762babe3$exports('cannot change access code', 400));
    //filter | argument ตามด้วยค่าใน DB ที่ Classroom สามารถเปลี่ยนเองได้
    const filterdBody = filterObject(req.body, 'name', 'color', 'users', 'rules', 'grader', 'calender', 'timetable', 'description');
    const updateClassroom = await $125027fea43c067a$exports.findByIdAndUpdate(req.Classroom.id, filterdBody, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            Classroom: updateClassroom
        }
    });
});
$21c44091d380f68a$export$8d9158a33355848 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const classrooms = await $125027fea43c067a$exports.find({
        'users.userId': req.user.id
    });
    if (!classrooms) return next(new $9cb55335762babe3$exports('class not found', 400));
    res.status(200).json({
        status: 'success',
        data: {
            classrooms: classrooms
        }
    });
});
$21c44091d380f68a$export$e3605f144727d735 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    //Always return as array
    const classrooms = await $125027fea43c067a$exports.find({
        accessCode: req.body.accessCode
    });
    //access the first and only classroom
    const classroom = classrooms[0];
    if (!classroom) return next(new $9cb55335762babe3$exports('classroom not found', 400));
    //Check if user already in this classroom
    classroom.users.forEach((el)=>{
        if (el.userId === req.user.id) return next(new $9cb55335762babe3$exports('Already join the classroom', 400));
    });
    // Add user to classroom
    const classroomNewUser = {
        userId: req.user.id,
        name: req.user.name,
        classroomRole: 'Student'
    };
    classroom.users.push(classroomNewUser);
    await classroom.save();
    // Add classroom to user
    const lineUser = await $fd22212e3c25cb5a$exports.findById(classroomNewUser.userId);
    const userNewClassroom = {
        classroomId: classroom.id,
        classroomName: classroom.name,
        classroomColor: classroom.color,
        classroomRole: 'Student'
    };
    lineUser.classrooms.push(userNewClassroom);
    await lineUser.save();
    res.status(200).json({
        status: 'success',
        data: {
            classroom: classroom,
            lineUser: lineUser
        }
    });
});
$21c44091d380f68a$export$f506e914f8dedfdc = (...roles)=>{
    return (req, res, next)=>{
        // role [ user, admin]
        if (!roles.includes(req.user.role)) return next(new $9cb55335762babe3$exports('you do not have permission', 403));
        next();
    };
};
$21c44091d380f68a$export$631f9d278801ba4 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // get Classroom
    const classroom = await $125027fea43c067a$exports.findById(req.query.classroomId);
    if (!classroom) return next(new $9cb55335762babe3$exports('classroom not found', 403));
    let userInClassroom;
    classroom.users.forEach((el)=>{
        if (el.userId === req.query.userId) userInClassroom = el;
    });
    if (!userInClassroom) return next(new $9cb55335762babe3$exports('user not belong in this classroom', 403));
    // get user from param that match
    const lineUser = await $fd22212e3c25cb5a$exports.findById(req.query.userId);
    if (!lineUser) return next(new $9cb55335762babe3$exports('line user not found', 403));
    // filter user object name ,pictureURL
    let newUserObject = $aa33edf437096a90$export$1039dc7987464938(lineUser, 'name');
    console.log(newUserObject);
    newUserObject = {
        ...userInClassroom,
        pictureURL: lineUser.pictureURL
    };
    // get submission
    const submissions = await $850feb170637aab1$exports.find({
        userId: req.query.userId,
        classroomId: req.query.classroomId
    });
    res.status(200).json({
        status: 'success',
        data: {
            newUserObject: newUserObject,
            submissions: submissions
        }
    });
});
$21c44091d380f68a$export$774968d3a7e3c13d = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    if (!req.query.classroomId) return next(new $9cb55335762babe3$exports('Invalid request', 400));
    // get Classroom
    const classroom = await $125027fea43c067a$exports.findById(req.query.classroomId);
    if (!classroom) return next(new $9cb55335762babe3$exports('classroom not found', 400));
    // get Content
    const assignments = await $a9dc971d056127bf$exports.find({
        type: 'assignment',
        classId: req.query.classroomId
    });
    // get submissions that belong in this classroom
    const submissions = await $850feb170637aab1$exports.find({
        classroomId: req.query.classroomId
    }).sort('contentId');
    const members = classroom.users.filter((member)=>member.classroomRole === 'Student'
    );
    const column = {
    };
    // First Column
    column['column0'] = {
        name: 'ชื่อนักเรียน',
        type: 'link',
        sortAble: true,
        sortInvert: true
    };
    column['column1'] = {
        name: 'รหัสนักเรียน',
        type: 'text',
        sortAble: true,
        sortInvert: true
    };
    // Mid Column
    assignments.forEach((assignment, index)=>{
        column[`column${index + 2}`] = {
            name: assignment.title,
            type: 'editField',
            sortAble: true,
            sortInvert: false
        };
    });
    //Aggregrate Column
    column['sum'] = {
        name: 'คะแนนรวม',
        type: 'number',
        sortAble: true,
        sortInvert: true
    };
    const memberSubmissions = members.map((member)=>{
        const row = {
            column0: {
                value: member.name,
                path: `../classroom-members/${member.userId}`
            }
        };
        row[`column1`] = {
            value: member.code,
            type: 'number'
        };
        let sumScore = 0;
        assignments.forEach((assignment, index)=>{
            const elementTemplate = {
                isSubmit: false,
                submissionScore: 0,
                element: null
            };
            submissions.forEach((submission)=>{
                if (submission.contentId === assignment.id && member.userId === submission.userId) {
                    elementTemplate.isSubmit = true;
                    elementTemplate.submissionScore = submission.score;
                    elementTemplate.submission = submission;
                }
            });
            row[`column${index + 2}`] = {
                value: elementTemplate.submissionScore,
                type: 'field',
                callback: null,
                editEnable: elementTemplate.isSubmit,
                element: elementTemplate.submission
            };
            sumScore += elementTemplate.submissionScore;
        });
        row[`sum`] = {
            value: sumScore,
            type: 'number'
        };
        return row;
    });
    res.status(200).json({
        status: 'success',
        data: {
            column: column,
            memberSubmissions: memberSubmissions
        }
    });
});



// create router from express
const $288c55e739a4086a$var$router = $3ezkb$express.Router();
// Normal route
$288c55e739a4086a$var$router.get('/getMyClassroom', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $21c44091d380f68a$export$8d9158a33355848);
$288c55e739a4086a$var$router.get('/getMemberInfo', $21c44091d380f68a$export$631f9d278801ba4);
$288c55e739a4086a$var$router.get('/getAllMembersAndSubmissions', $21c44091d380f68a$export$774968d3a7e3c13d);
$288c55e739a4086a$var$router.patch('/updateMyClassroom', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $21c44091d380f68a$export$722dc050e19ae38);
$288c55e739a4086a$var$router.post('/joinClassroom', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $21c44091d380f68a$export$e3605f144727d735);
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$288c55e739a4086a$var$router.route('/').get($21c44091d380f68a$export$163431112299797c).post($0bc8f3793ef000ed$export$fb0dc8052b1814d7, $21c44091d380f68a$export$d444b7d547b9817, $21c44091d380f68a$export$da844db56365444b);
$288c55e739a4086a$var$router.route('/:id').get($21c44091d380f68a$export$73c5e4cf93b51e2e).patch($21c44091d380f68a$export$d307a271b3ff1f0e).delete($21c44091d380f68a$export$68c77c1b6fffcad5);
$288c55e739a4086a$exports = $288c55e739a4086a$var$router;


var $068c75f6a5d645ce$exports = {};

// Adminstator API
//ROUTE HANDLER
var $eeaab96061374ff8$export$d2c7a3e0f82139;
var $eeaab96061374ff8$export$234c310f1a4fffd6;
var $eeaab96061374ff8$export$8d9d74d33575a548;
var $eeaab96061374ff8$export$5143cc956eb9d8f6;
var $eeaab96061374ff8$export$2bcf3daaf6ddd22d;
// Content public API
var $eeaab96061374ff8$export$2f9c6cb16e8b5b06;
// Content route
var $eeaab96061374ff8$export$c50583e978734f0d;




$eeaab96061374ff8$export$d2c7a3e0f82139 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $6c281682e6431d39$exports($a9dc971d056127bf$exports.find(), req.query).filter().sort().limitFields().paginate();
    const contents = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            contents: contents
        }
    });
});
$eeaab96061374ff8$export$234c310f1a4fffd6 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const content = await $a9dc971d056127bf$exports.findById(req.params.id);
    if (!content) return next(new $9cb55335762babe3$exports('no Content found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});
$eeaab96061374ff8$export$8d9d74d33575a548 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newContent = await $a9dc971d056127bf$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newContent: newContent
        }
    });
});
$eeaab96061374ff8$export$5143cc956eb9d8f6 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const content = await $a9dc971d056127bf$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!content) return next(new $9cb55335762babe3$exports('no Content found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});
$eeaab96061374ff8$export$2bcf3daaf6ddd22d = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const content = await $a9dc971d056127bf$exports.findByIdAndDelete(req.params.id);
    if (!content) return next(new $9cb55335762babe3$exports('no Content found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$eeaab96061374ff8$export$2f9c6cb16e8b5b06 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check condition
    //filter | argument ตามด้วยค่าใน DB ที่ Content สามารถเปลี่ยนเองได้
    /*
  const filterdBody = filterObject(
    req.body,
    'name',
    'color',
    'users',
    'rules',
    'grader',
    'calender',
    'timetable',
    'description'
  );*/ const updateContent = await $a9dc971d056127bf$exports.findByIdAndUpdate(req.content.id, req.body, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            content: updateContent
        }
    });
});
$eeaab96061374ff8$export$c50583e978734f0d = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const content = req.content;
    if (!content) return next(new $9cb55335762babe3$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});



// create router from express
const $068c75f6a5d645ce$var$router = $3ezkb$express.Router();
// Normal route
$068c75f6a5d645ce$var$router.get('/getMyContent', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $eeaab96061374ff8$export$c50583e978734f0d);
$068c75f6a5d645ce$var$router.patch('/updateMyContent', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $eeaab96061374ff8$export$2f9c6cb16e8b5b06);
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$068c75f6a5d645ce$var$router.route('/').get($eeaab96061374ff8$export$d2c7a3e0f82139).post($0bc8f3793ef000ed$export$fb0dc8052b1814d7, $eeaab96061374ff8$export$8d9d74d33575a548);
$068c75f6a5d645ce$var$router.route('/:id').get($eeaab96061374ff8$export$234c310f1a4fffd6).patch($eeaab96061374ff8$export$5143cc956eb9d8f6).delete($eeaab96061374ff8$export$2bcf3daaf6ddd22d);
$068c75f6a5d645ce$exports = $068c75f6a5d645ce$var$router;


var $5ead18ea0827c86d$exports = {};

// Adminstator API
//ROUTE HANDLER
var $8ad00299c6836b0d$export$84c830daf4bccc9d;
var $8ad00299c6836b0d$export$ba6b48d096545dd6;
var $8ad00299c6836b0d$export$2b8af209d02f8c4f;
var $8ad00299c6836b0d$export$cfe21b2eb92f0fe;
var $8ad00299c6836b0d$export$e604a691f7546e2f;
var $8ad00299c6836b0d$export$cc20771b1d6b487b;
// LineUser public API
var $8ad00299c6836b0d$export$7849be7286cc0b08;
// LineUser route
/**
 * Get the user from the request and return it.
 */ var $8ad00299c6836b0d$export$bee93532eb1cf2db;





$8ad00299c6836b0d$export$84c830daf4bccc9d = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $6c281682e6431d39$exports($fd22212e3c25cb5a$exports.find(), req.query).filter().sort().limitFields().paginate();
    const lineUsers = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            lineUsers: lineUsers
        }
    });
});
$8ad00299c6836b0d$export$ba6b48d096545dd6 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $fd22212e3c25cb5a$exports.findById(req.params.id);
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$8ad00299c6836b0d$export$2b8af209d02f8c4f = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newLineUser = await $fd22212e3c25cb5a$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newLineUser: newLineUser
        }
    });
});
$8ad00299c6836b0d$export$cfe21b2eb92f0fe = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $fd22212e3c25cb5a$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$8ad00299c6836b0d$export$e604a691f7546e2f = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = await $fd22212e3c25cb5a$exports.findByIdAndDelete(req.params.id);
    if (!user) return next(new $9cb55335762babe3$exports('no user found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$8ad00299c6836b0d$export$cc20771b1d6b487b = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const stats = await $fd22212e3c25cb5a$exports.aggregate([
        {
            $match: {
                number: {
                    $gte: 3
                }
            }
        },
        {
            $group: {
                _id: '$email',
                num: {
                    $sum: 1
                },
                sumNum: {
                    $sum: '$number'
                },
                avg: {
                    $avg: '$number'
                },
                min: {
                    $min: '$number'
                },
                max: {
                    $max: '$number'
                }
            }
        },
        {
            $sort: {
                avg: 1
            }
        },
        {
            $match: {
                _id: {
                    $ne: 'sorawit.nu@ku.th'
                }
            }
        }, 
    ]);
    res.status(200).json({
        status: 'success',
        data: {
            stats: stats
        }
    });
});
$8ad00299c6836b0d$export$7849be7286cc0b08 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
    const filterdBody = $aa33edf437096a90$export$1039dc7987464938(req.body, 'name');
    const updateLineUser = await $fd22212e3c25cb5a$exports.findByIdAndUpdate(req.user.id, filterdBody, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            user: updateLineUser
        }
    });
});
$8ad00299c6836b0d$export$bee93532eb1cf2db = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const user = req.user;
    if (!user) return next(new $9cb55335762babe3$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});



// create router from express
const $5ead18ea0827c86d$var$router = $3ezkb$express.Router();
$5ead18ea0827c86d$var$router.post('/login', $0bc8f3793ef000ed$export$199b5f9b35e82fdc);
$5ead18ea0827c86d$var$router.post('/signup', $0bc8f3793ef000ed$export$533fea6504b9ca2e);
$5ead18ea0827c86d$var$router.post('/isLogin', $0bc8f3793ef000ed$export$fb0dc8052b1814d7, $0bc8f3793ef000ed$export$e8ba96907705e541);
// CRUD Route  Authentication | Authorization | Responce
$5ead18ea0827c86d$var$router.route('/').get($0bc8f3793ef000ed$export$fb0dc8052b1814d7, $8ad00299c6836b0d$export$84c830daf4bccc9d).post($8ad00299c6836b0d$export$2b8af209d02f8c4f);
$5ead18ea0827c86d$var$router.route('/:id').get($8ad00299c6836b0d$export$ba6b48d096545dd6).patch($8ad00299c6836b0d$export$cfe21b2eb92f0fe).delete($0bc8f3793ef000ed$export$eda7ca9e36571553, $0bc8f3793ef000ed$export$e1bac762c84d3b0c('admin'), $8ad00299c6836b0d$export$e604a691f7546e2f);
$5ead18ea0827c86d$exports = $5ead18ea0827c86d$var$router;


var $997032d1a39dc545$exports = {};

// Adminstator API
//ROUTE HANDLER
var $1f9d2b758190831d$export$54cf0fce7b972b70;
var $1f9d2b758190831d$export$8b3ca78f81ec578c;
var $1f9d2b758190831d$export$522201eb69c6c5bc;
var $1f9d2b758190831d$export$4730664ce047e3bc;
var $1f9d2b758190831d$export$dccb98b97a3cb8be;
// File public API
var $1f9d2b758190831d$export$ff5246ded9208f61;
var $4c5b0baba87cb464$exports = {};


const $4c5b0baba87cb464$var$fileSchema = new $3ezkb$mongoose.Schema({
    filename: {
        type: String,
        default: 'default_content_name'
    },
    fileStackURL: String,
    fileStackHandle: String,
    size: Number,
    mimetype: String,
    fileStackUploadId: String,
    uploadDate: String,
    submissionId: String,
    contentId: String,
    isDeleted: {
        type: Boolean,
        default: false
    }
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
// เพิ่มเวลาสร้าง
$4c5b0baba87cb464$var$fileSchema.pre('save', function(next) {
    this.uploadDate = Date();
    next();
});
const $4c5b0baba87cb464$var$File = $3ezkb$mongoose.model('File', $4c5b0baba87cb464$var$fileSchema);
$4c5b0baba87cb464$exports = $4c5b0baba87cb464$var$File;





$1f9d2b758190831d$export$54cf0fce7b972b70 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $6c281682e6431d39$exports($4c5b0baba87cb464$exports.find(), req.query).filter().sort().limitFields().paginate();
    const files = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            files: files
        }
    });
});
$1f9d2b758190831d$export$8b3ca78f81ec578c = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const file = await $4c5b0baba87cb464$exports.findById(req.params.id);
    if (!file) return next(new $9cb55335762babe3$exports('no File found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            file: file
        }
    });
});
$1f9d2b758190831d$export$522201eb69c6c5bc = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newFile = await $4c5b0baba87cb464$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newFile: newFile
        }
    });
});
$1f9d2b758190831d$export$4730664ce047e3bc = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const file = await $4c5b0baba87cb464$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!file) return next(new $9cb55335762babe3$exports('no File found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            file: file
        }
    });
});
$1f9d2b758190831d$export$dccb98b97a3cb8be = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const file = await $4c5b0baba87cb464$exports.findByIdAndDelete(req.params.id);
    if (!file) return next(new $9cb55335762babe3$exports('no File found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$1f9d2b758190831d$export$ff5246ded9208f61 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check condition
    //filter | argument ตามด้วยค่าใน DB ที่ File สามารถเปลี่ยนเองได้
    /*
  const filterdBody = filterObject(
    req.body,
    'name',
    'color',
    'users',
    'rules',
    'grader',
    'calender',
    'timetable',
    'description'
  );*/ const updateFile = await $4c5b0baba87cb464$exports.findByIdAndUpdate(req.file.id, req.body, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            file: updateFile
        }
    });
});



// create router from express
const $997032d1a39dc545$var$router = $3ezkb$express.Router();
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$997032d1a39dc545$var$router.route('/').get($1f9d2b758190831d$export$54cf0fce7b972b70).post($1f9d2b758190831d$export$522201eb69c6c5bc);
$997032d1a39dc545$var$router.route('/:id').get($1f9d2b758190831d$export$8b3ca78f81ec578c).patch($1f9d2b758190831d$export$4730664ce047e3bc).delete($1f9d2b758190831d$export$dccb98b97a3cb8be);
$997032d1a39dc545$exports = $997032d1a39dc545$var$router;


var $b8ee5fbb6a21d638$exports = {};

// Adminstator API
//ROUTE HANDLER
var $c05c1d3c09ccba6e$export$42d55adf2cfb13be;
var $c05c1d3c09ccba6e$export$61563ab4d536a21a;
var $c05c1d3c09ccba6e$export$d8a23ed45dbe0e88;
var $c05c1d3c09ccba6e$export$c5d87aba6ea392e;
var $c05c1d3c09ccba6e$export$cbe52a2ce9da3186;
// Submission public API
var $c05c1d3c09ccba6e$export$fa96cf84814989c;
var $c05c1d3c09ccba6e$export$f738a15a5bc305f9;
var $c05c1d3c09ccba6e$export$1172fa5c481ae5b0;






$c05c1d3c09ccba6e$export$42d55adf2cfb13be = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $6c281682e6431d39$exports($850feb170637aab1$exports.find(), req.query).filter().sort().limitFields().paginate();
    const submissions = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            submissions: submissions
        }
    });
});
$c05c1d3c09ccba6e$export$61563ab4d536a21a = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const submission = await $850feb170637aab1$exports.findById(req.params.id);
    if (!submission) return next(new $9cb55335762babe3$exports('no Submission found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$c05c1d3c09ccba6e$export$d8a23ed45dbe0e88 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const newSubmission = await $850feb170637aab1$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newSubmission: newSubmission
        }
    });
});
$c05c1d3c09ccba6e$export$c5d87aba6ea392e = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const submission = await $850feb170637aab1$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!submission) return next(new $9cb55335762babe3$exports('no Submission found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$c05c1d3c09ccba6e$export$cbe52a2ce9da3186 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const submission = await $850feb170637aab1$exports.findByIdAndDelete(req.params.id);
    if (!submission) return next(new $9cb55335762babe3$exports('no Submission found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$c05c1d3c09ccba6e$export$fa96cf84814989c = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check condition
    //filter | argument ตามด้วยค่าใน DB ที่ Submission สามารถเปลี่ยนเองได้
    /*
  const filterdBody = filterObject(
    req.body,
    'name',
    'color',
    'users',
    'rules',
    'grader',
    'calender',
    'timetable',
    'description'
  );*/ const updateSubmission = await $850feb170637aab1$exports.findByIdAndUpdate(req.submission.id, req.body, {
        new: true,
        runValidators: true
    });
    //update document
    res.status(200).json({
        status: 'success',
        data: {
            submission: updateSubmission
        }
    });
});
$c05c1d3c09ccba6e$export$f738a15a5bc305f9 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    const submission = await $850feb170637aab1$exports.findOne({
        userId: req.user.id,
        contentId: req.body.contentId
    });
    if (!submission) return next(new $9cb55335762babe3$exports('submission not found', 400));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$c05c1d3c09ccba6e$export$1172fa5c481ae5b0 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    // check query
    if (!req.query.contentId) return next(new $9cb55335762babe3$exports('bad request', 400));
    // get submission
    const submissions = await $850feb170637aab1$exports.find({
        contentId: req.query.contentId
    });
    // get classroom
    // all submission are in the same classroom
    const classroom = await $125027fea43c067a$exports.findById(submissions[0].classroomId);
    const members = classroom.users;
    const files = await $4c5b0baba87cb464$exports.find({
        contentId: req.query.contentId
    });
    const submissionsAndFiles = [];
    submissions.forEach((el)=>{
        const tempObject = {
            member: {
            },
            id: el.id,
            comment: el.comment,
            score: el.score,
            isGraded: el.isGraded,
            userId: el.userId,
            contentId: el.contentId,
            classroomId: el.classroomId,
            isStudent: el.isStudent,
            submitDate: el.submitDate,
            files: []
        };
        members.forEach((member)=>{
            if (member.userId === el.userId) tempObject.member = member;
        });
        files.forEach((file)=>{
            if (file.submissionId === el.id) tempObject.files.push(file);
        });
        submissionsAndFiles.push(tempObject);
    });
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            submissionsAndFiles: submissionsAndFiles
        }
    });
});



// create router from express
const $b8ee5fbb6a21d638$var$router = $3ezkb$express.Router();
// normal route
$b8ee5fbb6a21d638$var$router.route('/getMySubmission').post($0bc8f3793ef000ed$export$fb0dc8052b1814d7, $c05c1d3c09ccba6e$export$f738a15a5bc305f9);
// Aggreatte route
$b8ee5fbb6a21d638$var$router.route('/getSubmissionsAndFile').get($c05c1d3c09ccba6e$export$1172fa5c481ae5b0);
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$b8ee5fbb6a21d638$var$router.route('/').get($c05c1d3c09ccba6e$export$42d55adf2cfb13be).post($c05c1d3c09ccba6e$export$d8a23ed45dbe0e88);
$b8ee5fbb6a21d638$var$router.route('/:id').get($c05c1d3c09ccba6e$export$61563ab4d536a21a).patch($c05c1d3c09ccba6e$export$c5d87aba6ea392e).delete($c05c1d3c09ccba6e$export$cbe52a2ce9da3186);
$b8ee5fbb6a21d638$exports = $b8ee5fbb6a21d638$var$router;


var $3fd4557a2109e006$exports = {};

var $2af9e74ec2863f1b$export$450fb1df401886c3;




const $2af9e74ec2863f1b$var$client = new $3ezkb$linebotsdk.Client({
    channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN
});
const $2af9e74ec2863f1b$var$handleConnectClassroom = async (event, accessCode)=>{
    const classroom = await $125027fea43c067a$exports.findOne({
        accessCode: accessCode
    });
    if (!classroom) return `ไม่พบห้องเรียนที่มีรหัสนั้น โปรดลองใหม่ในภายหลัง หากรอแล้วยังเกิดปัญหาอยู่ โปรดติดต่อฝ่ายสนับสนุนผลิตภัณท์`;
    // find owner lineUserId with the classroom owner id
    const lineUser = await $fd22212e3c25cb5a$exports.findById(classroom.users[0].userId);
    if (!lineUser) return `ข้อผิดพลาด: สมาชิกไม่ได้เป็นสมาชิกห้องเรียนนั้นๆ`;
    // check if user is owner
    if (event.source.userId !== lineUser.lineUserId) return `ข้อผิดพลาด: สมาชิกไม่ได้เป็นเจ้าของห้องเรียน`;
    // check if classroom already connected
    if (classroom.lineGroupChatId) return `ข้อผิดพลาด: ห้องเรียนนี้ถูกเชื่อมต่อกับกลุ่มสนทนาอื่นเรียบร้อยแล้ว`;
    // save groupchatId to classroom
    classroom.lineGroupChatId = event.source.groupId;
    classroom.save();
    return `เชื่อมต่อกับห้องเรียน ${classroom.name} สำเร็จ`;
};
const $2af9e74ec2863f1b$var$commandBlock = {
    connect: $2af9e74ec2863f1b$var$handleConnectClassroom,
    test: ()=>{
        return 'ทดสอบ 123';
    }
};
$2af9e74ec2863f1b$export$450fb1df401886c3 = $16c36c10cc7e291e$exports(async (req, res, next)=>{
    if (!req.body) res.status(400).json({
        status: 'fail'
    });
    const destination = req.body.destination;
    const events = req.body.events;
    const promises = events.map(async (event)=>{
        const message = {
            type: 'text',
            text: ''
        };
        let userMessage = event.message.text.trim();
        if (event.type === 'join') message.text = 'สวัสดีครับ ผมคือ Smart Classroom bot โดยผมจะทำหน้าที่ในการแจ้งเตือนข่าวสารต่างๆที่เกี่ยวข้องกับห้องเรียน ฝากตัวด้วยนะครับผม';
        if (userMessage.startsWith('$')) {
            // bot command
            let command = userMessage.slice(1, userMessage.length).split(' ');
            // mapping command to each case
            message.text = $2af9e74ec2863f1b$var$commandBlock[command[0]](event, command[1]);
        }
        if (message.text !== '') await $2af9e74ec2863f1b$var$client.replyMessage(`${event.replyToken}`, message);
    });
    await Promise.all(promises);
    res.status(200).json({
        status: 'success'
    });
});


// create router from express
const $3fd4557a2109e006$var$router = $3ezkb$express.Router();
// CRUD Route  Authentication | Authorization | Responce
$3fd4557a2109e006$var$router.route('/postLineMessage').post($2af9e74ec2863f1b$export$450fb1df401886c3);
$3fd4557a2109e006$exports = $3fd4557a2109e006$var$router;


const $7d1ce68b22eaf435$var$app = $3ezkb$express();
//Allow ALL CORS
$7d1ce68b22eaf435$var$app.use($3ezkb$cors());
// GLOBAL MIDDLEWARE
// Set security HTTP Header
$7d1ce68b22eaf435$var$app.use($3ezkb$helmet());
// Development loging request
if (process.env.NODE_ENV === 'development') $7d1ce68b22eaf435$var$app.use($3ezkb$morgan('dev'));
// Request limiter
// จำกัด 100 request ต่อ ip ในช่วง 1 ชั่วโมงเวลา
const $7d1ce68b22eaf435$var$limiter = $3ezkb$expressratelimit({
    max: 1000,
    windowMs: 3600000,
    message: 'Too many request, please try again in an hour'
});
$7d1ce68b22eaf435$var$app.use('/api', $7d1ce68b22eaf435$var$limiter);
// Body Parser to req.body
$7d1ce68b22eaf435$var$app.use($3ezkb$express.json({
    limit: '10kb'
}));
// Data Sanitization against noSQL query injection
$7d1ce68b22eaf435$var$app.use($3ezkb$expressmongosanitize());
// Data Sanitization against XSS
$7d1ce68b22eaf435$var$app.use($3ezkb$xssclean());
// Prevent Parameter Pollution
$7d1ce68b22eaf435$var$app.use($3ezkb$hpp());
// for access file on specifict path
$7d1ce68b22eaf435$var$app.use($3ezkb$express.static(`${__dirname}/public`));
// Put time in request
$7d1ce68b22eaf435$var$app.use((req, res, next)=>{
    req.requestTime = new Date().toISOString();
    //console.log(req.headers);
    next();
});
// Compress Response
$7d1ce68b22eaf435$var$app.use($3ezkb$compression());
// ROUTE
// route mouting
$7d1ce68b22eaf435$var$app.use('/api/users', $3e835eff6fbf8a5e$exports);
$7d1ce68b22eaf435$var$app.use('/api/classrooms', $288c55e739a4086a$exports);
$7d1ce68b22eaf435$var$app.use('/api/contents', $068c75f6a5d645ce$exports);
$7d1ce68b22eaf435$var$app.use('/api/lineUsers', $5ead18ea0827c86d$exports);
$7d1ce68b22eaf435$var$app.use('/api/files', $997032d1a39dc545$exports);
$7d1ce68b22eaf435$var$app.use('/api/submissions', $b8ee5fbb6a21d638$exports);
$7d1ce68b22eaf435$var$app.use('/api/lineAPI', $3fd4557a2109e006$exports);
// Unhandled route
$7d1ce68b22eaf435$var$app.all('*', (req, res, next)=>{
    next(new $9cb55335762babe3$exports(`Can't find the ${req.originalUrl}`, 404));
});
// GLOBAL HANDLING MIDDLEWARE
$7d1ce68b22eaf435$var$app.use($3c8c1d1e096e9f2d$exports);
$7d1ce68b22eaf435$exports = $7d1ce68b22eaf435$var$app;


const $d65e1b699027f727$var$DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);
// replace DB with process.env.DATABASE_LOCAL for local database
$3ezkb$mongoose.connect($d65e1b699027f727$var$DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    autoIndex: true,
    useFindAndModify: false
}).then(()=>{
    console.log('DB connection successful');
});
const $d65e1b699027f727$var$port = process.env.PORT || 5000;
const $d65e1b699027f727$var$server = $7d1ce68b22eaf435$exports.listen($d65e1b699027f727$var$port, ()=>{
    console.log(`app running on port ${$d65e1b699027f727$var$port}`);
});
process.on('unhandledRejection', (err)=>{
    console.log(err.name, err.message);
    console.log('UNHANDLE REJECTION !!! SHUTTING DOWN');
    $d65e1b699027f727$var$server.close(()=>{
        process.exit(1);
    });
});


//# sourceMappingURL=main.js.map
