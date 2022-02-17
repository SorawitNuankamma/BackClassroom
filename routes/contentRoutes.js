const express = require('express');
const contentController = require('../controller/contentController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Normal route
router.get(
  '/getMyContent',
  authController.loginOnly,
  contentController.getMyContent
);

router.patch(
  '/updateMyContent',
  authController.loginOnly,
  contentController.updateMyContent
);

// Aggreatte route

//TODO : Protect the route
// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(contentController.getAllContents)
  .post(contentController.postContent);

router
  .route('/:id')
  .get(contentController.getContent)
  .patch(contentController.updateContent)
  .delete(contentController.deleteContent);

module.exports = router;
