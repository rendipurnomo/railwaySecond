const express = require("express");
const router = express.Router();
const userController = require("../controllers/user.controller.js");
const { protect, protectAdmin } = require("../middleware/protect.js");

router.get("/",protect , userController.getUsers);
router.get("/:id", protect, userController.getUserById);
router.put("/:id", protect, userController.updateUser);
router.delete("/:id", protect, protectAdmin, userController.deleteUser);
router.patch("/roles/:id", protect, protectAdmin, userController.updateRolesUser);
router.patch("/event/:id", protect, protectAdmin, userController.updateEventUser);
router.patch("/resetEvent", protect, protectAdmin, userController.resetEventUser);

module.exports = router