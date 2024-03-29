const { PrismaClient } = require('@prisma/client');
const path = require('path');
const fs = require('fs');

const prisma = new PrismaClient();

exports.getUsers = async (req, res) => {
  try {
    const users = await prisma.users.findMany({
      orderBy: {
        createdAt: 'asc',
      },
    })
  
    if (!users) {
      return res.status(404).json({ message: 'Users not found' });
    }

    res.status(200).json({ users });
  } catch (error) {
    console.error(error); 
  }
}

exports.getUserById = async (req, res) => {
  const { id } = req.params;
  try {
    const user = await prisma.users.findUnique({
      where: { id: id },
    });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.updateUser = async (req, res) => {
  const { id } = req.params;
  const user = await prisma.users.findUnique({
    where: { id: id },
  });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  let fileName = '';
  if (req.files === null) {
    fileName = user.profilePic;
  } else {
    const file = req.files.file;
    const fileSize = file.data.length;
    const ext = path.extname(file.name);
    fileName = file.md5 + '_' + Date.now() + ext;
    const allowedType = ['.png', '.jpg', '.jpeg', '.webp'];

    if (!allowedType.includes(ext.toLowerCase())) {
      res.status(422).json({ message: 'Invalid Images' });
    }

    if (fileSize > 2000000) {
      res.status(422).json({ message: 'Image must be less than 2mb' });
    }

    const filePath = `src/public/images/${user.profilePic}`;
    fs.unlinkSync(filePath);

    file.mv(`src/public/images/${fileName}`, (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ msg: err.message });
      }
    });
  }
  const { fullName, username, email, address, phone } = req.body;
  const url = `${req.protocol}://${req.get('host')}/images/${fileName}`;
  try {
    const user = await prisma.users.update({
      where: { id: id },
      data: {
        fullName,
        username,
        email,
        address,
        phone,
        profilePic: fileName,
        picUrl: url,
      },
    });
    res.status(200).json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.updateRolesUser = async (req, res) => {
  const { id } = req.params;
  const user = await prisma.users.findUnique({
    where: { id: id },
  });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  try {
    const user = await prisma.users.update({
      where: { id: id },
      data: {
        roles: 'Member Istimewa',
      },
    });

    res
      .status(200)
      .json({ message: 'User updated role to Member Istimewa', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.updateEventUser = async (req, res) => {
  const { id } = req.params;
  const user = await prisma.users.findUnique({
    where: { id: id },
  });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }
  try {
    const user = await prisma.users.update({
      where: { id: id },
      data: {
        event: true,
      },
    });

    res.status(200).json({ message: 'User updated event to true', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.resetEventUser = async (req, res) => {
  try {
    const user = await prisma.users.updateMany({
      data: {
        event: false,
      },
    });

    res.status(200).json({ message: 'User updated event to false', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

exports.deleteUser = async (req, res) => {
  const { id } = req.params;
  try {
    const user = await prisma.users.delete({ where: { id: id } });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const filePath = `src/public/images/${user.profilePic}`;
    fs.unlinkSync(filePath);
    res.status(200).json({ message: 'User deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};