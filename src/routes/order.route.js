const express = require("express");
const router = express.Router();
const orderController = require("../controllers/order.controller.js");
const { protect, protectRoles, protectAdmin } = require("../middleware/protect.js");

router.get("/", protect, orderController.getOrders);
router.get("/:id", protect, orderController.getOrderByid);
router.post("/", protect, protectRoles, orderController.createOrder);
router.patch("/delivery/:id", protect, protectAdmin, orderController.updateDelivery);
router.patch("/payment/:id", protect, orderController.updatePayment);
router.delete("/:id", protect, protectAdmin, orderController.deleteOrder);

module.exports = router