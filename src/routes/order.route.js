const express = require("express");
const router = express.Router();
const orderController = require("../controllers/order.controller.js");
const { protect, protectRoles, protectAdmin } = require("../middleware/protect.js");

router.get("/", orderController.getOrders);
router.get("/:id", orderController.getOrderByid);
router.post("/", orderController.createOrder);
router.patch("/delivery/:id", orderController.updateDelivery);
router.patch("/payment/:id", orderController.updatePayment);
router.delete("/:id",orderController.deleteOrder);

module.exports = router