const express = require('express');
const classroomController = require('../controller/classroomController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Normal route
router.get(
  '/getMyClassroom',
  authController.loginOnly,
  classroomController.getMyClassroom
);

router.get('/getMemberInfo', classroomController.getMemberInfo);
router.get(
  '/getAllMembersAndSubmissions',
  classroomController.getAllMembersAndSubmissions
);

router.patch(
  '/updateMyClassroom',
  authController.loginOnly,
  classroomController.updateMyClassroom
);

router.post(
  '/joinClassroom',
  authController.loginOnly,
  classroomController.joinClassroom
);

// Aggreatte route

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(classroomController.getAllClassrooms)
  .post(
    authController.loginOnly,
    classroomController.formatPostRequest,
    classroomController.postClassroom
  );

router
  .route('/:id')
  .get(classroomController.getClassroom)
  .patch(classroomController.updateClassroom)
  .delete(classroomController.deleteClassroom);

module.exports = router;
