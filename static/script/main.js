let dateDropdown = document.getElementById('date-dropdown'); 

let currentYear = new Date().getFullYear();    
let earliestYear = 1970;     
while (currentYear >= earliestYear) {      
    let dateOption = document.createElement('option');          
    dateOption.text = currentYear;      
    dateOption.value = currentYear;        
    dateDropdown.add(dateOption);      
    currentYear -= 1;    
}

dateDropdown = document.getElementById('date-'); 

let currentYear1 = new Date().getFullYear();    
let earliestYear1 = 1970;     
while (currentYear1 >= earliestYear1) {      
  let dateOption = document.createElement('option');          
  dateOption.text = currentYear1;      
  dateOption.value = currentYear1;        
  dateDropdown.add(dateOption);      
  currentYear1 -= 1;    
}
