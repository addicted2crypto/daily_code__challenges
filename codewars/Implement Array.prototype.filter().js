// **Implement Array.prototype.filter()**


// What we want to implement is Array.prototype.filter() function, just like the existing Array.prototype.filter(). Another similar function is _.filter() in underscore.js and lodash.js.

// The usage will be quite simple, like:

// [1, 2, 3, 4, 5].filter(num => num > 3) == [4, 5]


/* My Solutions */

Array.prototype.filter = function (func) {
    const filteredNums = [];
    for(let i = 0; i < this.length; i++){
      if(func(this[i],i, this)){
        filteredNums.push(this[i]);
      }
    }
    return filteredNums;
   // OPTIONAL SOLUTION: 
  //  return this.reduce((acc, curr, index, arr) => {
  //     if (func(curr, index, arr)) acc.push(curr);
  //     return acc;
  //   }, []); or using reduce. both
    
  }
  