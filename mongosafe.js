const safe = [
  "$abs",
  "$acos",
  "$acosh",
  "$add",
  "$addToSet",
  "$allElementsTrue",
  "$and",
  "$anyElementTrue",
  "$arrayElemAt",
  "$arrayToObject",
  "$asin",
  "$asinh",
  "$atan",
  "$atan2",
  "$atanh",
  "$avg",
  "$ceil",
  "$cmp",
  "$concat",
  "$concatArrays",
  "$cond",
  "$convert",
  "$cos",
  "$dateFromParts",
  "$dateToParts",
  "$dateFromString",
  "$dateToString",
  "$dayOfMonth",
  "$dayOfWeek",
  "$dayOfYear",
  "$degreesToRadians",
  "$divide",
  "$eq",
  "$exp",
  "$exists",
  "$filter",
  "$first",
  "$floor",
  "$gt",
  "$gte",
  "$hour",
  "$ifNull",
  "$in",
  "$indexOfArray",
  "$indexOfBytes",
  "$indexOfCP",
  "$isArray",
  "$isoDayOfWeek",
  "$isoWeek",
  "$isoWeekYear",
  "$last",
  "$let",
  "$literal",
  "$ln",
  "$log",
  "$log10",
  "$lt",
  "$lte",
  "$ltrim",
  "$map",
  "$max",
  "$mergeObjects",
  "$min",
  "$millisecond",
  "$minute",
  "$mod",
  "$month",
  "$multiply",
  "$ne",
  "$not",
  "$objectToArray",
  "$or",
  "$pow",
  "$push",
  "$radiansToDegrees",
  "$range",
  "$reduce",
  "$regexFind",
  "$regexFindAll",
  "$regexMatch",
  "$reverseArray",
  "$round",
  "$rtrim",
  "$second",
  "$setDifference",
  "$setEquals",
  "$setIntersection",
  "$setIsSubset",
  "$setUnion",
  "$size",
  "$sin",
  "$slice",
  "$split",
  "$sqrt",
  "$stdDevPop",
  "$stdDevSamp",
  "$strcasecmp",
  "$strLenBytes",
  "$strLenCP",
  "$substr",
  "$substrBytes",
  "$substrCP",
  "$subtract",
  "$sum",
  "$switch",
  "$tan",
  "$toBool",
  "$toDate",
  "$toDecimal",
  "$toDouble",
  "$toInt",
  "$toLong",
  "$toObjectId",
  "$toString",
  "$toLower",
  "$toUpper",
  "$trim",
  "$trunc",
  "$type",
  "$week",
  "$year",
  "$zip",
  "$addFields",
  "$bucket",
  "$bucketAuto",
  "$count",
  "$facet",
  "$geoNear",
  "$group",
  "$limit",
  "$match",
  "$project",
  "$redact",
  "$replaceRoot",
  "$replaceWith",
  "$sample",
  "$set",
  "$skip",
  "$sort",
  "$sortByCount",
  "$unset",
  "$unwind"
].map(x => x.toLowerCase().trim())

exports.isSafe = (key) => !key.includes("$") || safe.includes(key.toLowerCase().trim())
