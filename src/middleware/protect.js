const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

exports.protect = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await prisma.users.findUnique({
      where: {
        id: decoded.userId,
      },
    });
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

exports.protectRoles = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await prisma.users.findUnique({
      where: {
        id: decoded.userId,
      },
    });
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (user.roles !== "Member Istimewa" && user.roles !== "Admin") {
      return res
        .status(401)
        .json({ message: "Hanya Bisa Di akses oleh Member Istimewa" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

exports.protectAdmin = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await prisma.users.findUnique({
      where: {
        id: decoded.userId,
      },
    });
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (user.roles !== "Admin") {
      return res.status(401).json({ message: "Akses Terlarang" });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

exports.protectEvent = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await prisma.users.findUnique({
      where: {
        id: decoded.userId,
      },
    });
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    if (user.event === false) {
      return res
        .status(401)
        .json({
          message:
            "Item Ini Hanya Bisa Di akses oleh Member yang mengikuti event",
        });
    }
    req.user = user;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
