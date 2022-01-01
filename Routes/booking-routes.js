const express = require("express");
const authController = require("../Controllers/auth-controller");
const bookingController = require("../Controllers/booking-controller");

const router = express.Router();

router.route("/checkout-session/:tourId")
.get(authController.protect, bookController.getCheckoutSession);