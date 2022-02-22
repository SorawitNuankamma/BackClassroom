const Classroom = require('../models/classroomModel');
const LineUser = require('../models/lineUserModel');
const Content = require('../models/contentModel');
const Submission = require('../models/submissionModel');
const APIFeatures = require('../utils/apifeatures');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');
const utility = require('../utils/utility');

exports.formatPostRequest = catchAsync(async (req, res, next) => {
  //Validate data
  //packing data
  const classroomObject = {
    name: req.body.name,
    description: req.body.description,
    color: req.body.color,
    users: [],
    rules: req.body.rules,
    meetingLink: req.body.meetingLink,
    grader: [],
    calender: [],
    timetable: req.body.timetable,
  };
  classroomObject.users.push({
    userId: req.user.id,
    name: req.user.name,
    classroomRole: 'Owner',
  });
  req.body = classroomObject;

  next();
});

// Adminstator API
//ROUTE HANDLER
exports.getAllClassrooms = catchAsync(async (req, res, next) => {
  // EXECUTE QUERY FOR IMPLEMENT ( AWAIT จะได้ผลลัพท์เป็น promise object ต้องเอา query แยกไว้)
  //console.log(query);
  // TODO : Fix query
  const features = new APIFeatures(Classroom.find(), req.query)
    .filter()
    .sort()
    .limitFields()
    .paginate();
  const classrooms = await features.query;

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    data: {
      classrooms,
    },
  });
});

exports.getClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findById(req.params.id);
  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      classroom,
    },
  });
});

exports.postClassroom = catchAsync(async (req, res, next) => {
  const newClassroom = await Classroom.create(req.body);

  res.status(200).json({
    status: 'success',
    data: {
      newClassroom,
    },
  });
});

exports.updateClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  });

  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      classroom,
    },
  });
});

exports.deleteClassroom = catchAsync(async (req, res, next) => {
  const classroom = await Classroom.findByIdAndDelete(req.params.id);

  if (!classroom) {
    return next(new AppError('no Classroom found with that id', 404));
  }

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

// Classroom public API
exports.updateMyClassroom = catchAsync(async (req, res, next) => {
  // check condition
  if (req.body.accessCode) {
    return next(new AppError('cannot change access code', 400));
  }

  //filter | argument ตามด้วยค่าใน DB ที่ Classroom สามารถเปลี่ยนเองได้
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
  );
  const updateClassroom = await Classroom.findByIdAndUpdate(
    req.Classroom.id,
    filterdBody,
    {
      new: true,
      runValidators: true,
    }
  );

  //update document

  res.status(200).json({
    status: 'success',
    data: {
      Classroom: updateClassroom,
    },
  });
});

// Classroom route
exports.getMyClassroom = catchAsync(async (req, res, next) => {
  const classrooms = await Classroom.find({ 'users.userId': req.user.id });

  if (!classrooms) {
    return next(new AppError('class not found', 400));
  }

  res.status(200).json({
    status: 'success',
    data: {
      classrooms,
    },
  });
});

exports.joinClassroom = catchAsync(async (req, res, next) => {
  //Always return as array
  const classrooms = await Classroom.find({ accessCode: req.body.accessCode });
  //access the first and only classroom
  const classroom = classrooms[0];

  if (!classroom) {
    return next(new AppError('classroom not found', 400));
  }

  //Check if user already in this classroom
  classroom.users.forEach((el) => {
    if (el.userId === req.user.id) {
      return next(new AppError('Already join the classroom', 400));
    }
  });

  // Add user to classroom
  const classroomNewUser = {
    userId: req.user.id,
    name: req.user.name,
    classroomRole: 'Student',
    lineUserId: req.user.lineUserId,
  };

  classroom.users.push(classroomNewUser);
  await classroom.save();

  // Add classroom to user
  const lineUser = await LineUser.findById(classroomNewUser.userId);
  const userNewClassroom = {
    classroomId: classroom.id,
    classroomName: classroom.name,
    classroomColor: classroom.color,
    classroomRole: 'Student',
  };
  lineUser.classrooms.push(userNewClassroom);
  await lineUser.save();

  res.status(200).json({
    status: 'success',
    data: {
      classroom,
      lineUser,
    },
  });
});

//
exports.authorizeFor = (...roles) => {
  return (req, res, next) => {
    // role [ user, admin]
    if (!roles.includes(req.user.role)) {
      return next(new AppError('you do not have permission', 403));
    }

    next();
  };
};

// Classroom route
exports.getMemberInfo = catchAsync(async (req, res, next) => {
  // get Classroom

  const classroom = await Classroom.findById(req.query.classroomId);
  if (!classroom) {
    return next(new AppError('classroom not found', 403));
  }

  let userInClassroom;
  classroom.users.forEach((el) => {
    if (el.userId === req.query.userId) {
      userInClassroom = el;
    }
  });
  if (!userInClassroom) {
    return next(new AppError('user not belong in this classroom', 403));
  }

  // get user from param that match
  const lineUser = await LineUser.findById(req.query.userId);
  if (!lineUser) {
    return next(new AppError('line user not found', 403));
  }
  // filter user object name ,pictureURL
  let newUserObject = utility.filterObject(lineUser, 'name');
  console.log(newUserObject);

  newUserObject = { ...userInClassroom, pictureURL: lineUser.pictureURL };

  // get submission
  const submissions = await Submission.find({
    userId: req.query.userId,
    classroomId: req.query.classroomId,
  });

  res.status(200).json({
    status: 'success',
    data: {
      newUserObject,
      submissions,
    },
  });
});

// Classroom route
exports.getAllMembersAndSubmissions = catchAsync(async (req, res, next) => {
  if (!req.query.classroomId) {
    return next(new AppError('Invalid request', 400));
  }

  // get Classroom
  const classroom = await Classroom.findById(req.query.classroomId);
  if (!classroom) {
    return next(new AppError('classroom not found', 400));
  }

  // get Content
  const assignments = await Content.find({
    type: 'assignment',
    classId: req.query.classroomId,
  });

  // get submissions that belong in this classroom
  const submissions = await Submission.find({
    classroomId: req.query.classroomId,
  }).sort('contentId');

  const members = classroom.users.filter(
    (member) => member.classroomRole === 'Student'
  );

  const column = {};

  // First Column
  column['column0'] = {
    name: 'ชื่อนักเรียน',
    type: 'link',
    sortAble: true,
    sortInvert: true,
  };

  column['column1'] = {
    name: 'รหัสนักเรียน',
    type: 'text',
    sortAble: true,
    sortInvert: true,
  };

  // Mid Column
  assignments.forEach((assignment, index) => {
    column[`column${index + 2}`] = {
      name: assignment.title,
      type: 'editField',
      sortAble: true,
      sortInvert: false,
    };
  });

  //Aggregrate Column
  column['sum'] = {
    name: 'คะแนนรวม',
    type: 'number',
    sortAble: true,
    sortInvert: true,
  };

  const memberSubmissions = members.map((member) => {
    const row = {
      column0: {
        value: member.name,
        path: `../classroom-members/${member.userId}`,
      },
    };
    row[`column1`] = {
      value: member.code,
      type: 'number',
    };

    let sumScore = 0;
    assignments.forEach((assignment, index) => {
      const elementTemplate = {
        isSubmit: false,
        submissionScore: 0,
        element: null,
      };
      submissions.forEach((submission) => {
        if (
          submission.contentId === assignment.id &&
          member.userId === submission.userId
        ) {
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
        element: elementTemplate.submission,
      };
      sumScore += elementTemplate.submissionScore;
    });

    row[`sum`] = {
      value: sumScore,
      type: 'number',
    };

    return row;
  });

  res.status(200).json({
    status: 'success',
    data: {
      column,
      memberSubmissions,
    },
  });
});
