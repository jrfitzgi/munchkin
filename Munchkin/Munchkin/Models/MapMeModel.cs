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
        [DataType(DataType.Text)]
        [Display(Name = "User Initials")]
        public string UserInitials { get; set; }

        [DataType(DataType.Text)]
        [Display(Name = "Zoom Level")]
        public string ZoomLevel { get; set; }

        [Required]
        [DataType(DataType.Text)]
        [Display(Name = "Co-ordinates")]
        public string Coordinates { get; set; }

        public MapMeModel()
        {
            this.UserInitials = "JF";
            this.Coordinates = "47.619048,-122.35384";
            this.ZoomLevel = "10";
        }
    }

}
