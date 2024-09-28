using System;
using System.Text.Json.Serialization;

namespace Flipify.Models
{
    public class Flipcard
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid FlipcardSetId { get; set; }
        public string NativeWord { get; set; }
        public string ForeignWord { get; set; }
        public string NativeWordExample { get; set; }
        public string ForeignWordExample { get; set; }
        public DateTime LastReviewDate { get; set; } = DateTime.UtcNow;
        public DateTime NextReviewDate { get; set; } = DateTime.UtcNow;
        public int IntervalDays { get; set; } = 1;
        public decimal Ef { get; set; } = 2.5m;
        public int AttemptCount { get; set; } = 0;

        [JsonIgnore]
        public FlipcardSet FlipcardSet { get; set; }
    }
}
