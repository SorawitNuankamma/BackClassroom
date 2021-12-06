const User = require('../models/userModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Utility
const filterObject = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) {
      newObj[el] = obj[el];
    }
  });
  return newObj;
};

// Adminstator API
//ROUTE HANDLER
exports.getAllUsers = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  const features = new APIFeatures(User.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const users = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      users,
    },
  });
});

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.postUser = catchAsync(async (req, res, next) => {
  const newUser = await User.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newUser,
    },
  });
});

exports.updateUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});

exports.deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);

  if (!user) {
    return next(new AppError('no user found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

exports.getUserStats = catchAsync(async (req, res, next) => {
  const stats = await User.aggregate([
    {
      $match: { number: { $gte: 3 } },
    },
    {
      $group: {
        _id: '$email',
        num: { $sum: 1 },
        sumNum: { $sum: '$number' },
        avg: { $avg: '$number' },
        min: { $min: '$number' },
        max: { $max: '$number' },
      },
    },
    {
      $sort: { avg: 1 },
    },
    {
      $match: { _id: { $ne: 'sorawit.nu@ku.th' } },
    },
  ]);
  res.status(200).json({
    status: 'success',
    data: {
      stats,
    },
  });
});

// User public API

exports.updateMyUser = catchAsync(async (req, res, next) => {
  // check condition
  if (req.body.password) {
    return next(new AppError('cannot change password on this route', 400));
  }

  //filter | argument ตามด้วยค่าใน DB ที่ user สามารถเปลี่ยนเองได้
  const filterdBody = filterObject(req.body, 'name');
  const updateUser = await User.findByIdAndUpdate(req.user.id, filterdBody, {
    new: true,
    runValidators: true,
  });

  //update document

  res.status(200).json({
    status: 'success',
    data: {
      user: updateUser,
    },
  });
});
