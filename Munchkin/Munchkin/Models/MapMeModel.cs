using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Globalization;
using System.Web.Mvc;
using System.Web.Security;

namespace Munchkin.Models
{
    public class MapMeModel
    {
        [Required]
        [Display(Name = "User Initials")]
        public string UserInitials { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Co-ordinates")]
        public string Coordinates { get; set; }

        public MapMeModel()
        {
            this.Coordinates = "1,1";
        }
    }

}
