using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EasyPKIView;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var CAs = ADCertificationAuthority.GetAll()
                                                  .Where(p => p.Templates.Where(q => q.RequiresPrivateKeyArchival).Any()).ToList();
            CAs.ForEach(p => Console.WriteLine(p.Config));
            Console.ReadKey();
        }
    }
}
