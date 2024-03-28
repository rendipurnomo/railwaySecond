const express = require("express");
const router = express.Router();
const userController = require("../controllers/user.controller.js");

router.get("/",userController.getUsers);
router.get("/:id",userController.getUserById);
router.put("/:id",userController.updateUser);
router.delete("/:id", userController.deleteUser);
router.patch("/roles/:id",userController.updateRolesUser);
router.patch("/event/:id", userController.updateEventUser);
router.patch("/resetEvent", userController.resetEventUser);

module.exports = router