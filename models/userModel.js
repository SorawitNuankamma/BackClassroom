const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      default: 'default_user_name',
      maxlength: [20, 'a name should not be longer than 10 character'],
      minlength: [3, 'a name must be longer than 3 character'],
      validator: [validator.isAlpha, 'must only contain character'],
    },
    lineID: {
      type: String,
    },
    email: {
      type: String,
      unique: true,
      validate: [validator.isEmail, 'must be an valid email'],
    },
    role: {
      type: String,
      enum: ['user', 'admin'],
      default: 'user',
    },
    photo: String,
    password: {
      type: String,
      require: [true, 'Password is require'],
      minlength: [8, 'a password must be longer than 8 character'],
      select: false,
    },
    passwordChangedAt: Date,
    classrooms: {
      type: Array,
      default: [],
    },
    passwordResetToken: String,
    passwordResetExpire: Date,
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

/*
userSchema.virtual('virtualNumber').get(function () {
  return this.number * 2;
});
*/

// Document Middleware for hashing password
userSchema.pre('save', async function (next) {
  // only run if passwod are modify
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// method คือ function ที่ call ได้ทุกที่กับ object นี้
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimeStamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimeStamp < changedTimestamp;
  }
  return false;
};

// เพิ่มเวลาเปลี่ยน password ครั้งล่าสุดใน database
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpire = Date.now() + 10 * 60 * 1000;

  //console.log({ resetToken }, this.passwordResetToken);

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
