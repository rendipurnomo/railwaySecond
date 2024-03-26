const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();

exports.getOrders = async (req, res) => {
  try {
    const orders = await prisma.orders.findMany({
      orderBy: {
        createdAt: "desc",
      }
    });
    if (orders.length === 0 || !orders) {
      return res.status(404).json({ message: "Belum ada order" });
    }
    res.status(200).json(orders);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.getOrderByid = async (req, res) => {
  const { username } = req.params;
  try {
    const order = await prisma.orders.findFirst({
      where: {
        username: username,
      },
    });
    if (!order) {
      return res.status(404).json({ message: "Order not found" });
    }
    res.status(200).json(order);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.createOrder = async (req, res) => {
  const {username,quantity, memo, totalPrice,address } = req.body;
  try {
    const order = await prisma.orders.create({
      data: {
        username: username,
        quantity: Number(quantity),
        pengiriman: address,
        memo: memo,
        totalPrice: totalPrice,
      },
    });

    res.status(201).json(order);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.updateDelivery = async (req, res) => {
  const { id } = req.params;
  const order = await prisma.orders.findUnique({
    where: { id: id },
  });

  if (!order) {
    return res.status(404).json({ message: "Order not found" });
  }

  try {
    const order = await prisma.orders.update({
      where: { id: id },
      data: {
        delivery: true,
      },
    });

    res.status(200).json({ message: "Order updated delivery", order });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

exports.updatePayment = async (req, res) => {
  const { id } = req.params;
  const order = await prisma.orderItem.findUnique({
    where: { id: id },
  });

  if (!order) {
    return res.status(404).json({ message: "Order not found" });
  }

  try {
    const order = await prisma.orders.update({
      where: { id: id },
      data: {
        paid: true,
      },
    });

    res.status(200).json({ message: "Order updated payment", order });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

exports.deleteOrder = async (req, res) => {
  const { id } = req.params;
  const order = await prisma.orders.findUnique({
    where: { id: id },
  });

  if (!order) {
    return res.status(404).json({ message: "Order not found" });
  }
  try {
    await prisma.orders.delete({
      where: {
        id: id,
      },
    });

    res.status(200).json({ message: "Order deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};
