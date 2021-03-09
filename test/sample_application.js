


console.log("Hello World");


var factory = require('../build_emcc/app/app.js');

factory().then((instance) => {
    // instance._sayHi(); // direct calling works
    // instance.ccall("sayHi"); // using ccall etc. also work
    // console.log(instance._daysInWeek()); // values can be returned, etc.

    var create_address_table = instance.cwrap('create_address_table', 'number', ['string']);
    var table_size = instance.cwrap('table_size', 'number');
    var get_source_line = instance.cwrap('get_source_line', 'string', ['number']);
    var get_target_line = instance.cwrap('get_target_line', 'string', ['number']);


    console.log(table_size());
    var ret = create_address_table('./working/test/NucleoProject.elf')
    console.log(table_size());

    var array = []; // empty array

    var size = table_size();
    for(i = 0; i < size; ++i) {
        array.push({ source_line: get_source_line(i), target_line: get_target_line(i) });
    }

    for (var i = 0; i < array.length; i++) {
        console.log(array[i].source_line);
        console.log(array[i].target_line);
        console.log(" ");
      }


  });



