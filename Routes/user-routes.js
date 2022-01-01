const express = require("express");
const authController = require("../Controllers/auth-controller");
const userController = require("../Controllers/user-controller");

const router = express.Router();

// Auth routes
router.route("/login").post(authController.login);
router.route("/sign-up").post(authController.signup);
router.route("/forgot-password").post(authController.forgotPassword);
router.route("/reset-password/:token").patch(authController.resetPassword);


router
  .route("/update-my-password")
  .patch(authController.protect, authController.updatePassword);
router
  .route("/update-my-details")
  .patch(
    authController.protect,
    userController.noPasswordUpdate,
    userController.uploadUserPhoto,
    userController.resizePhoto,
    userController.updateUser
  );
router
  .route("/me")
  .get(authController.protect, userController.getMe, userController.getUser);
router
  .route("/delete-me")
  .delete(authController.protect, userController.deleteUser);

router
  .route("/:id")
  .get(
    authController.protect,
    authController.checkRole("admin"),
    userController.getUser
  )
  .delete(
    authController.protect,
    authController.checkRole("admin"),
    userController.deleteUserPer
  );
  
// User routes
router.route("/").get(userController.getAllUsers);

module.exports = router;
