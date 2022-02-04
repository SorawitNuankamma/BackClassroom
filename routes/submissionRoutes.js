const express = require('express');
const submissionController = require('../controller/submissionController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();
// normal route
router
  .route('/getMySubmission')
  .post(authController.loginOnly, submissionController.getMySubmission);

// Aggreatte route
router
  .route('/getSubmissionsAndFile')
  .get(submissionController.getAllSubmissionsAndFile);

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(submissionController.getAllSubmissions)
  .post(submissionController.postSubmission);

router
  .route('/:id')
  .get(submissionController.getSubmission)
  .patch(submissionController.updateSubmission)
  .delete(submissionController.deleteSubmission);

module.exports = router;
