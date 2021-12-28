const express = require('express');
const userController = require('../controller/userController');
const authController = require('../controller/authController');

// create router from express
const router = express.Router();

// Normal route
router.get('/getMyUser', authController.protect, userController.getMyUser);

router.post('/signup', authController.signup);
router.post('/login', authController.login);

router.post('/isLogin', authController.protect, authController.isLogin);

router.post('/forgetPassword', authController.forgetPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.patch(
  '/updatePassword',
  authController.protect,
  authController.updatePassword
);
router.patch(
  '/updateMyUser',
  authController.protect,
  userController.updateMyUser
);

// Aggreatte route
router.route('/users-stats').get(userController.getUserStats);

// CRUD Route  Authentication | Authorization | Responce
router
  .route('/')
  .get(authController.protect, userController.getAllUsers)
  .post(userController.postUser);

router
  .route('/:id')
  .get(userController.getUser)
  .patch(userController.updateUser)
  .delete(
    authController.protect,
    authController.restrictTo('admin'),
    userController.deleteUser
  );

module.exports = router;
