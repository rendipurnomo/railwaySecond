-- AlterTable
ALTER TABLE `product` MODIFY `position` ENUM('EVENT', 'REKOMENDASI', 'TERBARU', 'TERLARIS', 'PROMO') NOT NULL;