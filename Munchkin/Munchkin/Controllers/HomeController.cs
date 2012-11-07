using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Munchkin.Models;

namespace Munchkin.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Message = "C# Munchkin 2";

            return View();
        }

        public ActionResult MapMe()
        {
            ViewBag.Message = "Maps your co-ordinates";
            MapMeModel mmm = new MapMeModel();
            return View(mmm);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult MapMe(MapMeModel model)
        {
            if (ModelState.IsValid && !String.IsNullOrWhiteSpace(model.Coordinates))
            {
                return View(model);
            }

            return MapMe();
        }

        public ActionResult MyLocation()
        {
            ViewBag.Message = "My Location";

            return View(new MapMeModel());
        }
    }
}
