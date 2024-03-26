const {PrismaClient} = require('@prisma/client')
const path = require('path')
const fs = require('fs')
const prisma = new PrismaClient()

exports.getBanners = async (req, res) => {
  try {
    const banners = await prisma.banners.findMany();
    if (banners.length === 0 || !banners) {
      return res.status(404).json({ message: 'Banner not found' });
    }
    res.status(200).json(banners);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
}

exports.createBanner = async (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0 || !req.files.file) {
    return res.status(400).json({ message: 'No files were uploaded.' });
  }

  const file = req.files.file;
  const fileSize = file.data.length;
  const ext = path.extname(file.name);
  const fileName = file.md5 + '_' + Date.now() + ext;
  const url = `${req.protocol}://${req.get('host')}/banners/${fileName}`;
  const allowedType = ['.png', '.jpg', '.jpeg'];

  if (!allowedType.includes(ext.toLowerCase())) {
    res.status(422).json({ msg: 'Invalid Images' });
  }

  if (fileSize > 2000000) {
    res.status(422).json({ msg: 'Image must be less than 2mb' });
  }
  const { name } =
    req.body;
  if (
    !name
  ) {
    return res.status(400).json({ message: 'Please fill in all fields' });
  }
  file.mv(`src/public/banners/${fileName}`, async (err) => {
    if (err) {
      return res.status(500).json({ message: err.message });
    }
    try {
    await prisma.banners.create({
      data: {
        name,
        image: fileName,
        ImageUrl: url,
      },
    });
    res.status(201).json({ message: 'Banners created!' });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
  });
}

exports.updateBanner = async (req, res) => {
  const { id } = req.params;
  const banner = await prisma.banners.findUnique({
    where: { id: id },
  });

  if (!banner) {
    return res.status(404).json({ message: 'Banner not found' });
  }

  let fileName = '';
  if (req.files === null) {
    fileName = banner.image;
  } else {
    const file = req.files.file;
    const fileSize = file.data.length;
    const ext = path.extname(file.name);
    fileName = file.md5 + '_' + Date.now() + ext;
    const allowedType = ['.png', '.jpg', '.jpeg'];

    if (!allowedType.includes(ext.toLowerCase())) {
      res.status(422).json({ msg: 'Invalid Images' });
    }

    if (fileSize > 2000000) {
      res.status(422).json({ msg: 'Image must be less than 2mb' });
    }

    const filePath = `src/public/banners/${banner.image}`;
    fs.unlinkSync(filePath);
    const { name } =
      req.body;
    const url = `${req.protocol}://${req.get('host')}/banners/${fileName}`;

    file.mv(`src/public/banners/${fileName}`, async (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ msg: err.message });
      }
      try {
        const banner = await prisma.banners.update({
          where: { id: id },
          data: {
            name,
            image: fileName,
            ImageUrl: url,
          },
        });
        res.status(200).json({ message: 'Banner updated', banner });
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });
  }
};

exports.deleteBanner = async (req, res) => {
  const { id } = req.params;
  const banner = await prisma.banners.findUnique({
    where: { id: id },
  });

  if (!banner) {
    return res.status(404).json({ message: 'Banner not found' });
  }

  const filePath = `src/public/banners/${banner.image}`;
  fs.unlinkSync(filePath);

  try {
    await prisma.banners.delete({
      where: { id: id },
    });
    res.status(200).json({ message: 'Banner deleted Success!' });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
}