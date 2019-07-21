'use strict';
module.exports = (sequelize, DataTypes) => {
  const Produit = sequelize.define('Produit', {
    name: DataTypes.STRING,
    price: DataTypes.FLOAT,
    photo: DataTypes.STRING,
    desc: DataTypes.STRING
  }, {});
  Produit.associate = function(models) {
    // associations can be defined here
  };
  return Produit;
};