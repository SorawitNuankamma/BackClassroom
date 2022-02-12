var $dL89m$mongoose = require("mongoose");
var $dL89m$dotenv = require("dotenv");
var $dL89m$express = require("express");
var $dL89m$morgan = require("morgan");
var $dL89m$expressratelimit = require("express-rate-limit");
var $dL89m$helmet = require("helmet");
var $dL89m$expressmongosanitize = require("express-mongo-sanitize");
var $dL89m$xssclean = require("xss-clean");
var $dL89m$hpp = require("hpp");
var $dL89m$compression = require("compression");
var $dL89m$cors = require("cors");
var $dL89m$validator = require("validator");
var $dL89m$bcryptjs = require("bcryptjs");
var $dL89m$crypto = require("crypto");
var $dL89m$nodefetch = require("node-fetch");
var $dL89m$jsonwebtoken = require("jsonwebtoken");
var $dL89m$util = require("util");
var $dL89m$nodemailer = require("nodemailer");
var $dL89m$linebotsdk = require("@line/bot-sdk");



process.on('uncaughtException', (err)=>{
    console.log('UNCAUGHT REJECTION !!! SHUTTING DOWN');
    console.log(err.name, err.message);
    process.exit(1);
});
$dL89m$dotenv.config({
    path: './config.env'
});
var $00c326f5cbdfa451$exports = {};
var $0f06555d84cc8559$exports = {};
class $0f06555d84cc8559$var$AppError extends Error {
    constructor(message, statusCode){
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
$0f06555d84cc8559$exports = $0f06555d84cc8559$var$AppError;


var $f9615974dfd74ba1$exports = {};

const $f9615974dfd74ba1$var$handleJWTExpiredError = ()=>new $0f06555d84cc8559$exports('your token has expire, please login again', 401)
;
const $f9615974dfd74ba1$var$handleJWTError = ()=>new $0f06555d84cc8559$exports('Invalid token, please login again', 401)
;
const $f9615974dfd74ba1$var$handleDuplicateFieldsDB = (err)=>{
    const message = `Duplicate value`;
    let error = new $0f06555d84cc8559$exports(message, 400);
    return error;
};
const $f9615974dfd74ba1$var$handleCastErrorDB = (err)=>{
    const message = `Invalid ${err.path}: ${err.value}`;
    let error = new $0f06555d84cc8559$exports(message, 400);
    return error;
};
const $f9615974dfd74ba1$var$handleValidationErrorDB = (err)=>{
    const errors = Object.values(err.errors).map((el)=>el.message
    );
    const message = `Invalid data input ${errors.join(', ')}`;
    let error = new $0f06555d84cc8559$exports(message, 400);
    return error;
};
const $f9615974dfd74ba1$var$sendErrorDev = (err, res)=>{
    res.status(err.statusCode).json({
        status: err.status,
        error: err,
        message: err.message,
        stack: err.stack
    });
};
const $f9615974dfd74ba1$var$sendErrorProd = (err, res)=>{
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
$f9615974dfd74ba1$exports = (err, req, res, next)=>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';
    if (process.env.NODE_ENV === 'development') $f9615974dfd74ba1$var$sendErrorDev(err, res);
    else if (process.env.NODE_ENV === 'production') {
        let error = {
            ...err
        };
        //console.log(err);
        if (err.name == 'CastError') error = $f9615974dfd74ba1$var$handleCastErrorDB(error);
        if (err.code == 11000) error = $f9615974dfd74ba1$var$handleDuplicateFieldsDB(error);
        if (err.name == 'ValidationError') error = $f9615974dfd74ba1$var$handleValidationErrorDB(error);
        if (err.name == 'JsonWebTokenError') error = $f9615974dfd74ba1$var$handleJWTError();
        if (err.name == 'TokenExpiredError') error = $f9615974dfd74ba1$var$handleJWTExpiredError();
        $f9615974dfd74ba1$var$sendErrorProd(error, res);
    }
};











var $078b4f4f54d924f2$exports = {};

// Adminstator API
//ROUTE HANDLER
var $093eb5e8ba7fe556$export$69093b9c569a5b5b;
var $093eb5e8ba7fe556$export$7cbf767827cd68ba;
var $093eb5e8ba7fe556$export$402fbb8c0ae400db;
var $093eb5e8ba7fe556$export$e3ac7a5d19605772;
var $093eb5e8ba7fe556$export$7d0f10f273c0438a;
var $093eb5e8ba7fe556$export$59f3ba6b40e64e77;
// User public API
var $093eb5e8ba7fe556$export$46d0484665757df5;
// User route
var $093eb5e8ba7fe556$export$8ebc4b9f4a31a32;
var $6b2eb9dd666c773b$exports = {};




const $6b2eb9dd666c773b$var$userSchema = new $dL89m$mongoose.Schema({
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
            $dL89m$validator.isAlpha,
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
            $dL89m$validator.isEmail,
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
$6b2eb9dd666c773b$var$userSchema.pre('save', async function(next) {
    // only run if passwod are modify
    if (!this.isModified('password')) return next();
    this.password = await $dL89m$bcryptjs.hash(this.password, 12);
    next();
});
// method คือ function ที่ call ได้ทุกที่กับ object นี้
$6b2eb9dd666c773b$var$userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
    return await $dL89m$bcryptjs.compare(candidatePassword, userPassword);
};
$6b2eb9dd666c773b$var$userSchema.methods.changedPasswordAfter = function(JWTTimeStamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimeStamp < changedTimestamp;
    }
    return false;
};
// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
$6b2eb9dd666c773b$var$userSchema.pre('save', function(next) {
    if (!this.isModified('password') || this.isNew) return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
});
$6b2eb9dd666c773b$var$userSchema.methods.createPasswordResetToken = function() {
    const resetToken = $dL89m$crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = $dL89m$crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpire = Date.now() + 600000;
    //console.log({ resetToken }, this.passwordResetToken);
    return resetToken;
};
const $6b2eb9dd666c773b$var$User = $dL89m$mongoose.model('User', $6b2eb9dd666c773b$var$userSchema);
$6b2eb9dd666c773b$exports = $6b2eb9dd666c773b$var$User;


var $55f17ad6fa001eb3$exports = {};
class $55f17ad6fa001eb3$var$APIFeatures {
    constructor(query, queryString){
        this.query = query;
        this.queryString = queryString;
    }
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
}
$55f17ad6fa001eb3$exports = $55f17ad6fa001eb3$var$APIFeatures;



var $e656ab11e72a4a5b$exports = {};
$e656ab11e72a4a5b$exports = (fn)=>{
    return (req, res, next)=>{
        fn(req, res, next).catch(next);
    };
};


/**
 * Filter an object by passing in an array of allowed fields.
 */ var $cb61cb180f13dc11$export$1039dc7987464938;
$cb61cb180f13dc11$export$1039dc7987464938 = (obj, ...allowedFields)=>{
    const newObj = {
    };
    Object.keys(obj).forEach((el)=>{
        if (allowedFields.includes(el)) newObj[el] = obj[el];
    });
    return newObj;
};


$093eb5e8ba7fe556$export$69093b9c569a5b5b = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $55f17ad6fa001eb3$exports($6b2eb9dd666c773b$exports.find(), req.query).filter().sort().limitFields().paginate();
    const users = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            users: users
        }
    });
});
$093eb5e8ba7fe556$export$7cbf767827cd68ba = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $6b2eb9dd666c773b$exports.findById(req.params.id);
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$093eb5e8ba7fe556$export$402fbb8c0ae400db = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newUser = await $6b2eb9dd666c773b$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newUser: newUser
        }
    });
});
$093eb5e8ba7fe556$export$e3ac7a5d19605772 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $6b2eb9dd666c773b$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$093eb5e8ba7fe556$export$7d0f10f273c0438a = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $6b2eb9dd666c773b$exports.findByIdAndDelete(req.params.id);
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$093eb5e8ba7fe556$export$59f3ba6b40e64e77 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const stats = await $6b2eb9dd666c773b$exports.aggregate([
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
$093eb5e8ba7fe556$export$46d0484665757df5 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // check condition
    if (req.body.password) return next(new $0f06555d84cc8559$exports('cannot change password on this route', 400));
    //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
    const filterdBody = $cb61cb180f13dc11$export$1039dc7987464938(req.body, 'name');
    const updateUser = await $6b2eb9dd666c773b$exports.findByIdAndUpdate(req.user.id, filterdBody, {
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
$093eb5e8ba7fe556$export$8ebc4b9f4a31a32 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = req.user;
    if (!user) return next(new $0f06555d84cc8559$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});


var $5d6a51c83223dc26$export$7200a869094fec36;
var $5d6a51c83223dc26$export$596d806903d1f59e;
//Middleware function for protect route
var $5d6a51c83223dc26$export$eda7ca9e36571553;
var $5d6a51c83223dc26$export$e1bac762c84d3b0c;
var $5d6a51c83223dc26$export$37ac0238687b67ae;
var $5d6a51c83223dc26$export$dc726c8e334dd814;
var $5d6a51c83223dc26$export$e2853351e15b7895;
var $5d6a51c83223dc26$export$e8ba96907705e541;
var $5d6a51c83223dc26$export$199b5f9b35e82fdc;
var $5d6a51c83223dc26$export$533fea6504b9ca2e;
//Middleware function for protect route
var $5d6a51c83223dc26$export$fb0dc8052b1814d7;



var $cd9cfbd9f361ed27$exports = {};




const $cd9cfbd9f361ed27$var$lineUserSchema = new $dL89m$mongoose.Schema({
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
            $dL89m$validator.isAlpha,
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
const $cd9cfbd9f361ed27$var$LineUser = $dL89m$mongoose.model('LineUser', $cd9cfbd9f361ed27$var$lineUserSchema);
$cd9cfbd9f361ed27$exports = $cd9cfbd9f361ed27$var$LineUser;




var $cdcc1f41035bbf43$exports = {};

const $cdcc1f41035bbf43$var$sendEmail = async (options)=>{
    // Create a transporter
    const transporter = $dL89m$nodemailer.createTransport({
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
$cdcc1f41035bbf43$exports = $cdcc1f41035bbf43$var$sendEmail;




var $5d6a51c83223dc26$require$promisify = $dL89m$util.promisify;
const $5d6a51c83223dc26$var$verifyLineToken = async (token)=>{
    const response = await $dL89m$nodefetch(`https://api.line.me/oauth2/v2.1/verify?access_token=${token}`, {
        method: 'GET',
        mode: 'cors'
    });
    return response.json(); // parses JSON response into native JavaScript objects
};
const $5d6a51c83223dc26$var$getLineUserProfile = async (token)=>{
    const response = await $dL89m$nodefetch(`https://api.line.me/v2/profile`, {
        method: 'GET',
        mode: 'cors',
        headers: {
            Authorization: 'Bearer ' + token
        }
    });
    return response.json(); // parses JSON response into native JavaScript objects
};
const $5d6a51c83223dc26$var$signToken = (id)=>{
    return $dL89m$jsonwebtoken.sign({
        id: id
    }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};
const $5d6a51c83223dc26$var$createSendToken = (user, statusCode, res)=>{
    const token = $5d6a51c83223dc26$var$signToken(user._id);
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
$5d6a51c83223dc26$export$7200a869094fec36 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newUser = await $6b2eb9dd666c773b$exports.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        lineID: req.body.lineID
    });
    $5d6a51c83223dc26$var$createSendToken(newUser, 201, res);
});
$5d6a51c83223dc26$export$596d806903d1f59e = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const { email: email , password: password  } = req.body;
    // check if email and password is exist
    if (!email || !password) return next(new $0f06555d84cc8559$exports('Please provide user and password', 400));
    // check if user exist and password correct
    const user = await $6b2eb9dd666c773b$exports.findOne({
        email: email
    }).select('+password');
    if (!user || !await user.correctPassword(password, user.password)) return next(new $0f06555d84cc8559$exports('Incorrect email or password', 401));
    $5d6a51c83223dc26$var$createSendToken(user, 200, res);
});
$5d6a51c83223dc26$export$eda7ca9e36571553 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    //console.log(token);
    if (!token) return next(new $0f06555d84cc8559$exports('You are not logged in!', 401));
    // verification the token
    const decoded = await $5d6a51c83223dc26$require$promisify($dL89m$jsonwebtoken.verify)(token, process.env.JWT_SECRET);
    // check if user still exist
    const currentUser = await $6b2eb9dd666c773b$exports.findById(decoded.id);
    if (!currentUser) return next(new $0f06555d84cc8559$exports('the token belong to this user is no longer exist', 401));
    // check if user changed password after the token was issue
    if (currentUser.changedPasswordAfter(decoded.iat)) return next(new $0f06555d84cc8559$exports('user password has been change, please login again', 401));
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});
$5d6a51c83223dc26$export$e1bac762c84d3b0c = (...roles)=>{
    return (req, res, next)=>{
        // role [ user, admin]
        if (!roles.includes(req.user.role)) return next(new $0f06555d84cc8559$exports('you do not have permission', 403));
        next();
    };
};
$5d6a51c83223dc26$export$37ac0238687b67ae = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // get user base on email
    const user = await $6b2eb9dd666c773b$exports.findOne({
        email: req.body.email
    });
    if (!user) return next(new $0f06555d84cc8559$exports('no user with that email', 404));
    // generate the random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({
        validateBeforeSave: false
    });
    // send it to user email
    const resetURL = `${req.protocol}://${req.get('host')}/api/users/resetPassword/${resetToken}`;
    const message = `submit the patch request to change you password to ${resetURL}`;
    try {
        await $cdcc1f41035bbf43$exports({
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
        return next(new $0f06555d84cc8559$exports('There was an error sending an email, try again later', 500));
    }
});
$5d6a51c83223dc26$export$dc726c8e334dd814 = async (req, res, next)=>{
    // get user base on the token
    const hashedToken = $dL89m$crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await $6b2eb9dd666c773b$exports.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpire: {
            $gt: Date.now()
        }
    });
    // if token has not expire, and there is a user, set the new password
    if (!user) return next(new $0f06555d84cc8559$exports('Token is invalid or has expired', 400));
    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    await user.save();
    // update changedPasswordAt property for the user
    // log the user in and send JWT
    $5d6a51c83223dc26$var$createSendToken(user, 200, res);
};
$5d6a51c83223dc26$export$e2853351e15b7895 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // get user
    let user = req.user;
    user = await $6b2eb9dd666c773b$exports.findById(req.user.id).select('+password');
    // check that current password that user provide is correct
    if (!user || !await user.correctPassword(req.body.password, user.password)) return next(new $0f06555d84cc8559$exports('Incorrect email or password', 401));
    // update the password
    user.password = req.body.newPassword;
    await user.save();
    // update changedPasswordAt property for the user
    // log the user in and send JWT
    $5d6a51c83223dc26$var$createSendToken(user, 200, res);
});
$5d6a51c83223dc26$export$e8ba96907705e541 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // SEND RESPONSE
    res.status(200).json({
        status: 'success'
    });
});
$5d6a51c83223dc26$export$199b5f9b35e82fdc = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    if (!token) return next(new $0f06555d84cc8559$exports('You are not provide a token!', 401));
    //DEVELOPMENT ONLY
    if (token === process.env.BYPASS_TOKEN) $cd9cfbd9f361ed27$exports.findOne({
        lineUserId: 'FAKELINEUSERID'
    }).then((lineUser)=>{
        if (!lineUser) return next(new $0f06555d84cc8559$exports('user not found', 401));
        $5d6a51c83223dc26$var$createSendToken(lineUser, 200, res);
    });
    if (token === process.env.BYPASS_TOKEN2) $cd9cfbd9f361ed27$exports.findOne({
        lineUserId: 'a1s0andf7us3r'
    }).then((lineUser)=>{
        if (!lineUser) return next(new $0f06555d84cc8559$exports('user not found', 401));
        $5d6a51c83223dc26$var$createSendToken(lineUser, 200, res);
    });
    //DEVELOPMENT ONLY END
    // verification the token
    // somehow can't figure out this to working with  await
    $5d6a51c83223dc26$var$verifyLineToken(token).then((verifyResult)=>{
        if (!verifyResult.client_id) return next(new $0f06555d84cc8559$exports('Invalid token or token are no longer valid', 401));
        //Use line token to get user information
        $5d6a51c83223dc26$var$getLineUserProfile(token).then((userProfile)=>{
            // check if line user already exist
            const lineUserId = userProfile.userId;
            $cd9cfbd9f361ed27$exports.findOne({
                lineUserId: lineUserId
            }).then((lineUser)=>{
                if (!lineUser) return next(new $0f06555d84cc8559$exports('user not found', 401));
                $5d6a51c83223dc26$var$createSendToken(lineUser, 200, res);
            });
        });
    });
});
$5d6a51c83223dc26$export$533fea6504b9ca2e = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    if (!token) return next(new $0f06555d84cc8559$exports('You are not provide a token!', 401));
    // verification the token
    // somehow can't figure out this to working with  await
    $5d6a51c83223dc26$var$verifyLineToken(token).then((verifyResult)=>{
        if (!verifyResult.client_id) return next(new $0f06555d84cc8559$exports('Invalid token or token are no longer valid', 401));
        //Use line token to get use information
        $5d6a51c83223dc26$var$getLineUserProfile(token).then((userProfile)=>{
            // save user profile in lineUser
            console.log(userProfile);
            $cd9cfbd9f361ed27$exports.create({
                name: userProfile.displayName,
                lineUserId: userProfile.userId,
                pictureURL: userProfile.pictureUrl
            }).then((newLineUser)=>{
                $5d6a51c83223dc26$var$createSendToken(newLineUser, 200, res);
            }).catch((err)=>{
                res.status(500).json({
                    status: 'fail',
                    error: err
                });
            });
        });
    });
});
$5d6a51c83223dc26$export$fb0dc8052b1814d7 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    let token;
    // get token and check token
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) token = req.headers.authorization.split(' ')[1];
    //console.log(token);
    if (!token) return next(new $0f06555d84cc8559$exports('You are not logged in!', 401));
    // verification the token
    const decoded = await $5d6a51c83223dc26$require$promisify($dL89m$jsonwebtoken.verify)(token, process.env.JWT_SECRET);
    // check if user still exist
    const currentUser = await $cd9cfbd9f361ed27$exports.findById(decoded.id);
    if (!currentUser) return next(new $0f06555d84cc8559$exports('the token belong to this user is no longer exist', 401));
    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});


// create router from express
const $078b4f4f54d924f2$var$router = $dL89m$express.Router();
// Normal route
$078b4f4f54d924f2$var$router.get('/getMyUser', $5d6a51c83223dc26$export$eda7ca9e36571553, $093eb5e8ba7fe556$export$8ebc4b9f4a31a32);
$078b4f4f54d924f2$var$router.post('/signup', $5d6a51c83223dc26$export$7200a869094fec36);
$078b4f4f54d924f2$var$router.post('/login', $5d6a51c83223dc26$export$596d806903d1f59e);
$078b4f4f54d924f2$var$router.post('/isLogin', $5d6a51c83223dc26$export$eda7ca9e36571553, $5d6a51c83223dc26$export$e8ba96907705e541);
$078b4f4f54d924f2$var$router.post('/forgetPassword', $5d6a51c83223dc26$export$37ac0238687b67ae);
$078b4f4f54d924f2$var$router.patch('/resetPassword/:token', $5d6a51c83223dc26$export$dc726c8e334dd814);
$078b4f4f54d924f2$var$router.patch('/updatePassword', $5d6a51c83223dc26$export$eda7ca9e36571553, $5d6a51c83223dc26$export$e2853351e15b7895);
$078b4f4f54d924f2$var$router.patch('/updateMyUser', $5d6a51c83223dc26$export$eda7ca9e36571553, $093eb5e8ba7fe556$export$46d0484665757df5);
// Aggreatte route
$078b4f4f54d924f2$var$router.route('/users-stats').get($093eb5e8ba7fe556$export$59f3ba6b40e64e77);
// CRUD Route  Authentication | Authorization | Responce
$078b4f4f54d924f2$var$router.route('/').get($5d6a51c83223dc26$export$eda7ca9e36571553, $093eb5e8ba7fe556$export$69093b9c569a5b5b).post($093eb5e8ba7fe556$export$402fbb8c0ae400db);
$078b4f4f54d924f2$var$router.route('/:id').get($093eb5e8ba7fe556$export$7cbf767827cd68ba).patch($093eb5e8ba7fe556$export$e3ac7a5d19605772).delete($5d6a51c83223dc26$export$eda7ca9e36571553, $5d6a51c83223dc26$export$e1bac762c84d3b0c('admin'), $093eb5e8ba7fe556$export$7d0f10f273c0438a);
$078b4f4f54d924f2$exports = $078b4f4f54d924f2$var$router;


var $08112f3e302690a6$exports = {};

var $bc1139c5d556ca67$export$d444b7d547b9817;
// Adminstator API
//ROUTE HANDLER
var $bc1139c5d556ca67$export$163431112299797c;
var $bc1139c5d556ca67$export$73c5e4cf93b51e2e;
var $bc1139c5d556ca67$export$da844db56365444b;
var $bc1139c5d556ca67$export$d307a271b3ff1f0e;
var $bc1139c5d556ca67$export$68c77c1b6fffcad5;
// Classroom public API
var $bc1139c5d556ca67$export$722dc050e19ae38;
// Classroom route
var $bc1139c5d556ca67$export$8d9158a33355848;
var $bc1139c5d556ca67$export$e3605f144727d735;
//
var $bc1139c5d556ca67$export$f506e914f8dedfdc;
// Classroom route
var $bc1139c5d556ca67$export$631f9d278801ba4;
// Classroom route
var $bc1139c5d556ca67$export$774968d3a7e3c13d;
var $3086ae1592ddd45b$exports = {};






const $3086ae1592ddd45b$var$classroomSchema = new $dL89m$mongoose.Schema({
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
            $dL89m$validator.isAlpha,
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
$3086ae1592ddd45b$var$classroomSchema.pre('save', function(next) {
    if (!this.isNew) return next();
    // Generate Room Code
    this.accessCode = $dL89m$crypto.randomBytes(3).toString('hex');
    next();
});
// Cascade Save
$3086ae1592ddd45b$var$classroomSchema.post('save', async function(doc) {
    const user = await $cd9cfbd9f361ed27$exports.findById(doc.users[0].userId);
    user.classrooms.push({
        classroomId: doc.id,
        classroomName: doc.name,
        classroomColor: doc.color,
        classroomRole: doc.users[0].classroomRole
    });
    await user.save();
});
// Cascade Delete
$3086ae1592ddd45b$var$classroomSchema.post('findOneAndDelete', async function(doc) {
    const user = await $cd9cfbd9f361ed27$exports.findById(doc.users[0].userId);
    user.classrooms = user.classrooms.filter((el)=>doc.id !== el.classroomId
    );
    await user.save();
});
const $3086ae1592ddd45b$var$Classroom = $dL89m$mongoose.model('Classroom', $3086ae1592ddd45b$var$classroomSchema);
$3086ae1592ddd45b$exports = $3086ae1592ddd45b$var$Classroom;



var $08e73fced338a401$exports = {};



const $08e73fced338a401$var$client = new $dL89m$linebotsdk.Client({
    channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN
});
const $08e73fced338a401$var$contentSchema = new $dL89m$mongoose.Schema({
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
            $dL89m$validator.isAlpha,
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
$08e73fced338a401$var$contentSchema.pre('save', function(next) {
    this.createDate = Date();
    next();
});
const $08e73fced338a401$var$Content = $dL89m$mongoose.model('Content', $08e73fced338a401$var$contentSchema);
$08e73fced338a401$exports = $08e73fced338a401$var$Content;


var $205a270a15d11e23$exports = {};


const $205a270a15d11e23$var$submissionSchema = new $dL89m$mongoose.Schema({
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
$205a270a15d11e23$var$submissionSchema.pre('save', function(next) {
    this.submitDate = Date();
    next();
});
const $205a270a15d11e23$var$Submission = $dL89m$mongoose.model('Submission', $205a270a15d11e23$var$submissionSchema);
$205a270a15d11e23$exports = $205a270a15d11e23$var$Submission;






$bc1139c5d556ca67$export$d444b7d547b9817 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
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
$bc1139c5d556ca67$export$163431112299797c = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    //console.log(query);
    // TODO : Fix query
    const features = new $55f17ad6fa001eb3$exports($3086ae1592ddd45b$exports.find(), req.query).filter().sort().limitFields().paginate();
    const classrooms = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            classrooms: classrooms
        }
    });
});
$bc1139c5d556ca67$export$73c5e4cf93b51e2e = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const classroom = await $3086ae1592ddd45b$exports.findById(req.params.id);
    if (!classroom) return next(new $0f06555d84cc8559$exports('no Classroom found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            classroom: classroom
        }
    });
});
$bc1139c5d556ca67$export$da844db56365444b = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newClassroom = await $3086ae1592ddd45b$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newClassroom: newClassroom
        }
    });
});
$bc1139c5d556ca67$export$d307a271b3ff1f0e = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const classroom = await $3086ae1592ddd45b$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!classroom) return next(new $0f06555d84cc8559$exports('no Classroom found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            classroom: classroom
        }
    });
});
$bc1139c5d556ca67$export$68c77c1b6fffcad5 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const classroom = await $3086ae1592ddd45b$exports.findByIdAndDelete(req.params.id);
    if (!classroom) return next(new $0f06555d84cc8559$exports('no Classroom found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$bc1139c5d556ca67$export$722dc050e19ae38 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // check condition
    if (req.body.accessCode) return next(new $0f06555d84cc8559$exports('cannot change access code', 400));
    //filter | argument ตามด้วยค่าใน DB ที่ Classroom สามารถเปลี่ยนเองได้
    const filterdBody = filterObject(req.body, 'name', 'color', 'users', 'rules', 'grader', 'calender', 'timetable', 'description');
    const updateClassroom = await $3086ae1592ddd45b$exports.findByIdAndUpdate(req.Classroom.id, filterdBody, {
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
$bc1139c5d556ca67$export$8d9158a33355848 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const classrooms = await $3086ae1592ddd45b$exports.find({
        'users.userId': req.user.id
    });
    if (!classrooms) return next(new $0f06555d84cc8559$exports('class not found', 400));
    res.status(200).json({
        status: 'success',
        data: {
            classrooms: classrooms
        }
    });
});
$bc1139c5d556ca67$export$e3605f144727d735 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    //Always return as array
    const classrooms = await $3086ae1592ddd45b$exports.find({
        accessCode: req.body.accessCode
    });
    //access the first and only classroom
    const classroom = classrooms[0];
    if (!classroom) return next(new $0f06555d84cc8559$exports('classroom not found', 400));
    //Check if user already in this classroom
    classroom.users.forEach((el)=>{
        if (el.userId === req.user.id) return next(new $0f06555d84cc8559$exports('Already join the classroom', 400));
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
    const lineUser = await $cd9cfbd9f361ed27$exports.findById(classroomNewUser.userId);
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
$bc1139c5d556ca67$export$f506e914f8dedfdc = (...roles)=>{
    return (req, res, next)=>{
        // role [ user, admin]
        if (!roles.includes(req.user.role)) return next(new $0f06555d84cc8559$exports('you do not have permission', 403));
        next();
    };
};
$bc1139c5d556ca67$export$631f9d278801ba4 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // get Classroom
    const classroom = await $3086ae1592ddd45b$exports.findById(req.query.classroomId);
    if (!classroom) return next(new $0f06555d84cc8559$exports('classroom not found', 403));
    let userInClassroom;
    classroom.users.forEach((el)=>{
        if (el.userId === req.query.userId) userInClassroom = el;
    });
    if (!userInClassroom) return next(new $0f06555d84cc8559$exports('user not belong in this classroom', 403));
    // get user from param that match
    const lineUser = await $cd9cfbd9f361ed27$exports.findById(req.query.userId);
    if (!lineUser) return next(new $0f06555d84cc8559$exports('line user not found', 403));
    // filter user object name ,pictureURL
    let newUserObject = $cb61cb180f13dc11$export$1039dc7987464938(lineUser, 'name');
    console.log(newUserObject);
    newUserObject = {
        ...userInClassroom,
        pictureURL: lineUser.pictureURL
    };
    // get submission
    const submissions = await $205a270a15d11e23$exports.find({
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
$bc1139c5d556ca67$export$774968d3a7e3c13d = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    if (!req.query.classroomId) return next(new $0f06555d84cc8559$exports('Invalid request', 400));
    // get Classroom
    const classroom = await $3086ae1592ddd45b$exports.findById(req.query.classroomId);
    if (!classroom) return next(new $0f06555d84cc8559$exports('classroom not found', 400));
    // get Content
    const assignments = await $08e73fced338a401$exports.find({
        type: 'assignment',
        classId: req.query.classroomId
    });
    // get submissions that belong in this classroom
    const submissions = await $205a270a15d11e23$exports.find({
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
const $08112f3e302690a6$var$router = $dL89m$express.Router();
// Normal route
$08112f3e302690a6$var$router.get('/getMyClassroom', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $bc1139c5d556ca67$export$8d9158a33355848);
$08112f3e302690a6$var$router.get('/getMemberInfo', $bc1139c5d556ca67$export$631f9d278801ba4);
$08112f3e302690a6$var$router.get('/getAllMembersAndSubmissions', $bc1139c5d556ca67$export$774968d3a7e3c13d);
$08112f3e302690a6$var$router.patch('/updateMyClassroom', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $bc1139c5d556ca67$export$722dc050e19ae38);
$08112f3e302690a6$var$router.post('/joinClassroom', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $bc1139c5d556ca67$export$e3605f144727d735);
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$08112f3e302690a6$var$router.route('/').get($bc1139c5d556ca67$export$163431112299797c).post($5d6a51c83223dc26$export$fb0dc8052b1814d7, $bc1139c5d556ca67$export$d444b7d547b9817, $bc1139c5d556ca67$export$da844db56365444b);
$08112f3e302690a6$var$router.route('/:id').get($bc1139c5d556ca67$export$73c5e4cf93b51e2e).patch($bc1139c5d556ca67$export$d307a271b3ff1f0e).delete($bc1139c5d556ca67$export$68c77c1b6fffcad5);
$08112f3e302690a6$exports = $08112f3e302690a6$var$router;


var $c768a71cc8a53382$exports = {};

// Adminstator API
//ROUTE HANDLER
var $c10eb8ab395b9b42$export$d2c7a3e0f82139;
var $c10eb8ab395b9b42$export$234c310f1a4fffd6;
var $c10eb8ab395b9b42$export$8d9d74d33575a548;
var $c10eb8ab395b9b42$export$5143cc956eb9d8f6;
var $c10eb8ab395b9b42$export$2bcf3daaf6ddd22d;
// Content public API
var $c10eb8ab395b9b42$export$2f9c6cb16e8b5b06;
// Content route
var $c10eb8ab395b9b42$export$c50583e978734f0d;




$c10eb8ab395b9b42$export$d2c7a3e0f82139 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $55f17ad6fa001eb3$exports($08e73fced338a401$exports.find(), req.query).filter().sort().limitFields().paginate();
    const contents = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            contents: contents
        }
    });
});
$c10eb8ab395b9b42$export$234c310f1a4fffd6 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const content = await $08e73fced338a401$exports.findById(req.params.id);
    if (!content) return next(new $0f06555d84cc8559$exports('no Content found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});
$c10eb8ab395b9b42$export$8d9d74d33575a548 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newContent = await $08e73fced338a401$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newContent: newContent
        }
    });
});
$c10eb8ab395b9b42$export$5143cc956eb9d8f6 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const content = await $08e73fced338a401$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!content) return next(new $0f06555d84cc8559$exports('no Content found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});
$c10eb8ab395b9b42$export$2bcf3daaf6ddd22d = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const content = await $08e73fced338a401$exports.findByIdAndDelete(req.params.id);
    if (!content) return next(new $0f06555d84cc8559$exports('no Content found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$c10eb8ab395b9b42$export$2f9c6cb16e8b5b06 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
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
  );*/ const updateContent = await $08e73fced338a401$exports.findByIdAndUpdate(req.content.id, req.body, {
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
$c10eb8ab395b9b42$export$c50583e978734f0d = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const content = req.content;
    if (!content) return next(new $0f06555d84cc8559$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            content: content
        }
    });
});



// create router from express
const $c768a71cc8a53382$var$router = $dL89m$express.Router();
// Normal route
$c768a71cc8a53382$var$router.get('/getMyContent', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $c10eb8ab395b9b42$export$c50583e978734f0d);
$c768a71cc8a53382$var$router.patch('/updateMyContent', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $c10eb8ab395b9b42$export$2f9c6cb16e8b5b06);
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$c768a71cc8a53382$var$router.route('/').get($c10eb8ab395b9b42$export$d2c7a3e0f82139).post($5d6a51c83223dc26$export$fb0dc8052b1814d7, $c10eb8ab395b9b42$export$8d9d74d33575a548);
$c768a71cc8a53382$var$router.route('/:id').get($c10eb8ab395b9b42$export$234c310f1a4fffd6).patch($c10eb8ab395b9b42$export$5143cc956eb9d8f6).delete($c10eb8ab395b9b42$export$2bcf3daaf6ddd22d);
$c768a71cc8a53382$exports = $c768a71cc8a53382$var$router;


var $a4a44aba8e1e9600$exports = {};

// Adminstator API
//ROUTE HANDLER
var $d576eea7b2e55089$export$84c830daf4bccc9d;
var $d576eea7b2e55089$export$ba6b48d096545dd6;
var $d576eea7b2e55089$export$2b8af209d02f8c4f;
var $d576eea7b2e55089$export$cfe21b2eb92f0fe;
var $d576eea7b2e55089$export$e604a691f7546e2f;
var $d576eea7b2e55089$export$cc20771b1d6b487b;
// LineUser public API
var $d576eea7b2e55089$export$7849be7286cc0b08;
// LineUser route
/**
 * Get the user from the request and return it.
 */ var $d576eea7b2e55089$export$bee93532eb1cf2db;





$d576eea7b2e55089$export$84c830daf4bccc9d = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $55f17ad6fa001eb3$exports($cd9cfbd9f361ed27$exports.find(), req.query).filter().sort().limitFields().paginate();
    const lineUsers = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            lineUsers: lineUsers
        }
    });
});
$d576eea7b2e55089$export$ba6b48d096545dd6 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $cd9cfbd9f361ed27$exports.findById(req.params.id);
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$d576eea7b2e55089$export$2b8af209d02f8c4f = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newLineUser = await $cd9cfbd9f361ed27$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newLineUser: newLineUser
        }
    });
});
$d576eea7b2e55089$export$cfe21b2eb92f0fe = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $cd9cfbd9f361ed27$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});
$d576eea7b2e55089$export$e604a691f7546e2f = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = await $cd9cfbd9f361ed27$exports.findByIdAndDelete(req.params.id);
    if (!user) return next(new $0f06555d84cc8559$exports('no user found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$d576eea7b2e55089$export$cc20771b1d6b487b = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const stats = await $cd9cfbd9f361ed27$exports.aggregate([
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
$d576eea7b2e55089$export$7849be7286cc0b08 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
    const filterdBody = $cb61cb180f13dc11$export$1039dc7987464938(req.body, 'name');
    const updateLineUser = await $cd9cfbd9f361ed27$exports.findByIdAndUpdate(req.user.id, filterdBody, {
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
$d576eea7b2e55089$export$bee93532eb1cf2db = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const user = req.user;
    if (!user) return next(new $0f06555d84cc8559$exports('unknown error', 404));
    res.status(200).json({
        status: 'success',
        data: {
            user: user
        }
    });
});



// create router from express
const $a4a44aba8e1e9600$var$router = $dL89m$express.Router();
$a4a44aba8e1e9600$var$router.post('/login', $5d6a51c83223dc26$export$199b5f9b35e82fdc);
$a4a44aba8e1e9600$var$router.post('/signup', $5d6a51c83223dc26$export$533fea6504b9ca2e);
$a4a44aba8e1e9600$var$router.post('/isLogin', $5d6a51c83223dc26$export$fb0dc8052b1814d7, $5d6a51c83223dc26$export$e8ba96907705e541);
// CRUD Route  Authentication | Authorization | Responce
$a4a44aba8e1e9600$var$router.route('/').get($5d6a51c83223dc26$export$fb0dc8052b1814d7, $d576eea7b2e55089$export$84c830daf4bccc9d).post($d576eea7b2e55089$export$2b8af209d02f8c4f);
$a4a44aba8e1e9600$var$router.route('/:id').get($d576eea7b2e55089$export$ba6b48d096545dd6).patch($d576eea7b2e55089$export$cfe21b2eb92f0fe).delete($5d6a51c83223dc26$export$eda7ca9e36571553, $5d6a51c83223dc26$export$e1bac762c84d3b0c('admin'), $d576eea7b2e55089$export$e604a691f7546e2f);
$a4a44aba8e1e9600$exports = $a4a44aba8e1e9600$var$router;


var $f048c3871b2af075$exports = {};

// Adminstator API
//ROUTE HANDLER
var $aa384ac0d58a966e$export$54cf0fce7b972b70;
var $aa384ac0d58a966e$export$8b3ca78f81ec578c;
var $aa384ac0d58a966e$export$522201eb69c6c5bc;
var $aa384ac0d58a966e$export$4730664ce047e3bc;
var $aa384ac0d58a966e$export$dccb98b97a3cb8be;
// File public API
var $aa384ac0d58a966e$export$ff5246ded9208f61;
var $5e05827d67b8819d$exports = {};


const $5e05827d67b8819d$var$fileSchema = new $dL89m$mongoose.Schema({
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
$5e05827d67b8819d$var$fileSchema.pre('save', function(next) {
    this.uploadDate = Date();
    next();
});
const $5e05827d67b8819d$var$File = $dL89m$mongoose.model('File', $5e05827d67b8819d$var$fileSchema);
$5e05827d67b8819d$exports = $5e05827d67b8819d$var$File;





$aa384ac0d58a966e$export$54cf0fce7b972b70 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $55f17ad6fa001eb3$exports($5e05827d67b8819d$exports.find(), req.query).filter().sort().limitFields().paginate();
    const files = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            files: files
        }
    });
});
$aa384ac0d58a966e$export$8b3ca78f81ec578c = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const file = await $5e05827d67b8819d$exports.findById(req.params.id);
    if (!file) return next(new $0f06555d84cc8559$exports('no File found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            file: file
        }
    });
});
$aa384ac0d58a966e$export$522201eb69c6c5bc = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newFile = await $5e05827d67b8819d$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newFile: newFile
        }
    });
});
$aa384ac0d58a966e$export$4730664ce047e3bc = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const file = await $5e05827d67b8819d$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!file) return next(new $0f06555d84cc8559$exports('no File found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            file: file
        }
    });
});
$aa384ac0d58a966e$export$dccb98b97a3cb8be = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const file = await $5e05827d67b8819d$exports.findByIdAndDelete(req.params.id);
    if (!file) return next(new $0f06555d84cc8559$exports('no File found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$aa384ac0d58a966e$export$ff5246ded9208f61 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
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
  );*/ const updateFile = await $5e05827d67b8819d$exports.findByIdAndUpdate(req.file.id, req.body, {
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
const $f048c3871b2af075$var$router = $dL89m$express.Router();
// Aggreatte route
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$f048c3871b2af075$var$router.route('/').get($aa384ac0d58a966e$export$54cf0fce7b972b70).post($aa384ac0d58a966e$export$522201eb69c6c5bc);
$f048c3871b2af075$var$router.route('/:id').get($aa384ac0d58a966e$export$8b3ca78f81ec578c).patch($aa384ac0d58a966e$export$4730664ce047e3bc).delete($aa384ac0d58a966e$export$dccb98b97a3cb8be);
$f048c3871b2af075$exports = $f048c3871b2af075$var$router;


var $57501d047387e24e$exports = {};

// Adminstator API
//ROUTE HANDLER
var $519cb29180e624d1$export$42d55adf2cfb13be;
var $519cb29180e624d1$export$61563ab4d536a21a;
var $519cb29180e624d1$export$d8a23ed45dbe0e88;
var $519cb29180e624d1$export$c5d87aba6ea392e;
var $519cb29180e624d1$export$cbe52a2ce9da3186;
// Submission public API
var $519cb29180e624d1$export$fa96cf84814989c;
var $519cb29180e624d1$export$f738a15a5bc305f9;
var $519cb29180e624d1$export$1172fa5c481ae5b0;






$519cb29180e624d1$export$42d55adf2cfb13be = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
    const features = new $55f17ad6fa001eb3$exports($205a270a15d11e23$exports.find(), req.query).filter().sort().limitFields().paginate();
    const submissions = await features.query;
    // SEND RESPONSE
    res.status(200).json({
        status: 'success',
        data: {
            submissions: submissions
        }
    });
});
$519cb29180e624d1$export$61563ab4d536a21a = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const submission = await $205a270a15d11e23$exports.findById(req.params.id);
    if (!submission) return next(new $0f06555d84cc8559$exports('no Submission found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$519cb29180e624d1$export$d8a23ed45dbe0e88 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const newSubmission = await $205a270a15d11e23$exports.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            newSubmission: newSubmission
        }
    });
});
$519cb29180e624d1$export$c5d87aba6ea392e = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const submission = await $205a270a15d11e23$exports.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true
    });
    if (!submission) return next(new $0f06555d84cc8559$exports('no Submission found with that id', 404));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$519cb29180e624d1$export$cbe52a2ce9da3186 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const submission = await $205a270a15d11e23$exports.findByIdAndDelete(req.params.id);
    if (!submission) return next(new $0f06555d84cc8559$exports('no Submission found with that id', 404));
    res.status(204).json({
        status: 'success',
        data: null
    });
});
$519cb29180e624d1$export$fa96cf84814989c = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
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
  );*/ const updateSubmission = await $205a270a15d11e23$exports.findByIdAndUpdate(req.submission.id, req.body, {
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
$519cb29180e624d1$export$f738a15a5bc305f9 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    const submission = await $205a270a15d11e23$exports.findOne({
        userId: req.user.id,
        contentId: req.body.contentId
    });
    if (!submission) return next(new $0f06555d84cc8559$exports('submission not found', 400));
    res.status(200).json({
        status: 'success',
        data: {
            submission: submission
        }
    });
});
$519cb29180e624d1$export$1172fa5c481ae5b0 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
    // check query
    if (!req.query.contentId) return next(new $0f06555d84cc8559$exports('bad request', 400));
    // get submission
    const submissions = await $205a270a15d11e23$exports.find({
        contentId: req.query.contentId
    });
    // get classroom
    // all submission are in the same classroom
    const classroom = await $3086ae1592ddd45b$exports.findById(submissions[0].classroomId);
    const members = classroom.users;
    const files = await $5e05827d67b8819d$exports.find({
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
const $57501d047387e24e$var$router = $dL89m$express.Router();
// normal route
$57501d047387e24e$var$router.route('/getMySubmission').post($5d6a51c83223dc26$export$fb0dc8052b1814d7, $519cb29180e624d1$export$f738a15a5bc305f9);
// Aggreatte route
$57501d047387e24e$var$router.route('/getSubmissionsAndFile').get($519cb29180e624d1$export$1172fa5c481ae5b0);
//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
$57501d047387e24e$var$router.route('/').get($519cb29180e624d1$export$42d55adf2cfb13be).post($519cb29180e624d1$export$d8a23ed45dbe0e88);
$57501d047387e24e$var$router.route('/:id').get($519cb29180e624d1$export$61563ab4d536a21a).patch($519cb29180e624d1$export$c5d87aba6ea392e).delete($519cb29180e624d1$export$cbe52a2ce9da3186);
$57501d047387e24e$exports = $57501d047387e24e$var$router;


var $6f2f5a23976cedda$exports = {};

var $2e6d647c80a4fc87$export$450fb1df401886c3;




const $2e6d647c80a4fc87$var$client = new $dL89m$linebotsdk.Client({
    channelAccessToken: `0S82MK8Q8Db9CqR4lh26Tr9qoU16U5p4RS0xfIXBEGne7zHYpq7plHgEMCW8TCgss85IrcWwrRdfP5q0VoMHFrOB1850fGdkiw9y0rX61cblBm5KfC/0FDr7yazl+SY7wo4eOcNlF4E74WjZIumo0wdB04t89/1O/w1cDnyilFU=`
});
const $2e6d647c80a4fc87$var$handleConnectClassroom = async (event, accessCode)=>{
    const classroom = await $3086ae1592ddd45b$exports.findOne({
        accessCode: accessCode
    });
    if (!classroom) return `ไม่พบห้องเรียนที่มีรหัสนั้น โปรดลองใหม่ในภายหลัง หากรอแล้วยังเกิดปัญหาอยู่ โปรดติดต่อฝ่ายสนับสนุนผลิตภัณท์`;
    // find owner lineUserId with the classroom owner id
    const lineUser = await $cd9cfbd9f361ed27$exports.findById(classroom.users[0].userId);
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
const $2e6d647c80a4fc87$var$commandBlock = {
    connect: $2e6d647c80a4fc87$var$handleConnectClassroom,
    test: ()=>{
        return 'ทดสอบ 123';
    }
};
$2e6d647c80a4fc87$export$450fb1df401886c3 = $e656ab11e72a4a5b$exports(async (req, res, next)=>{
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
            message.text = $2e6d647c80a4fc87$var$commandBlock[command[0]](event, command[1]);
        }
        if (message.text !== '') await $2e6d647c80a4fc87$var$client.replyMessage(`${event.replyToken}`, message);
    });
    await Promise.all(promises);
    res.status(200).json({
        status: 'success'
    });
});


// create router from express
const $6f2f5a23976cedda$var$router = $dL89m$express.Router();
// CRUD Route  Authentication | Authorization | Responce
$6f2f5a23976cedda$var$router.route('/postLineMessage').post($2e6d647c80a4fc87$export$450fb1df401886c3);
$6f2f5a23976cedda$exports = $6f2f5a23976cedda$var$router;


const $00c326f5cbdfa451$var$app = $dL89m$express();
//Allow ALL CORS
$00c326f5cbdfa451$var$app.use($dL89m$cors());
// GLOBAL MIDDLEWARE
// Set security HTTP Header
$00c326f5cbdfa451$var$app.use($dL89m$helmet());
// Development loging request
if (process.env.NODE_ENV === 'development') $00c326f5cbdfa451$var$app.use($dL89m$morgan('dev'));
// Request limiter
// จำกัด 100 request ต่อ ip ในช่วง 1 ชั่วโมงเวลา
const $00c326f5cbdfa451$var$limiter = $dL89m$expressratelimit({
    max: 1000,
    windowMs: 3600000,
    message: 'Too many request, please try again in an hour'
});
$00c326f5cbdfa451$var$app.use('/api', $00c326f5cbdfa451$var$limiter);
// Body Parser to req.body
$00c326f5cbdfa451$var$app.use($dL89m$express.json({
    limit: '10kb'
}));
// Data Sanitization against noSQL query injection
$00c326f5cbdfa451$var$app.use($dL89m$expressmongosanitize());
// Data Sanitization against XSS
$00c326f5cbdfa451$var$app.use($dL89m$xssclean());
// Prevent Parameter Pollution
$00c326f5cbdfa451$var$app.use($dL89m$hpp());
// for access file on specifict path
$00c326f5cbdfa451$var$app.use($dL89m$express.static(`${__dirname}/public`));
// Put time in request
$00c326f5cbdfa451$var$app.use((req, res, next)=>{
    req.requestTime = new Date().toISOString();
    //console.log(req.headers);
    next();
});
// Compress Response
$00c326f5cbdfa451$var$app.use($dL89m$compression());
// ROUTE
// route mouting
$00c326f5cbdfa451$var$app.use('/api/users', $078b4f4f54d924f2$exports);
$00c326f5cbdfa451$var$app.use('/api/classrooms', $08112f3e302690a6$exports);
$00c326f5cbdfa451$var$app.use('/api/contents', $c768a71cc8a53382$exports);
$00c326f5cbdfa451$var$app.use('/api/lineUsers', $a4a44aba8e1e9600$exports);
$00c326f5cbdfa451$var$app.use('/api/files', $f048c3871b2af075$exports);
$00c326f5cbdfa451$var$app.use('/api/submissions', $57501d047387e24e$exports);
$00c326f5cbdfa451$var$app.use('/api/lineAPI', $6f2f5a23976cedda$exports);
// Unhandled route
$00c326f5cbdfa451$var$app.all('*', (req, res, next)=>{
    next(new $0f06555d84cc8559$exports(`Can't find the ${req.originalUrl}`, 404));
});
// GLOBAL HANDLING MIDDLEWARE
$00c326f5cbdfa451$var$app.use($f9615974dfd74ba1$exports);
$00c326f5cbdfa451$exports = $00c326f5cbdfa451$var$app;


const $e849b6ff98d2fbf0$var$DB = process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD);
// replace DB with process.env.DATABASE_LOCAL for local database
$dL89m$mongoose.connect($e849b6ff98d2fbf0$var$DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    autoIndex: true,
    useFindAndModify: false
}).then(()=>{
    console.log('DB connection successful');
});
const $e849b6ff98d2fbf0$var$port = process.env.PORT || 5000;
const $e849b6ff98d2fbf0$var$server = $00c326f5cbdfa451$exports.listen($e849b6ff98d2fbf0$var$port, ()=>{
    console.log(`app running on port ${$e849b6ff98d2fbf0$var$port}`);
});
process.on('unhandledRejection', (err)=>{
    console.log(err.name, err.message);
    console.log('UNHANDLE REJECTION !!! SHUTTING DOWN');
    $e849b6ff98d2fbf0$var$server.close(()=>{
        process.exit(1);
    });
});


//# sourceMappingURL=main.js.map
