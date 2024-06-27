// models/shipper.js
const { DataTypes } = require('sequelize');
const sequelize = require('./index');
const Shipper = sequelize.define('Shipper', {
 shipperID: {
 type: DataTypes.INTEGER,
 primaryKey: true,
 autoIncrement: true
 },
 shipperName: {
 type: DataTypes.STRING,
 allowNull: false
 },
 phone: {
 type: DataTypes.STRING,
 allowNull: false
 }
});
module.exports = Shipper;
