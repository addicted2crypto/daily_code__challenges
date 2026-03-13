// Leetcode 3090 - Minimum Operations to Make Array Elements Divisible by 3

// You are given an integer array nums. In one operation, you can add or subtract 1 from any element of nums.
// Return the minimum number of operations to make all elements of nums divisible by 3.

// Example 1:
// Input: nums = [1,2,3,4]
// Output: 3
// Explanation:
// Subtract 1 from 1. (1 -> 0)
// Add 1 to 2.       (2 -> 3)
// Subtract 1 from 4. (4 -> 3)

// Example 2:
// Input: nums = [3,6,9]
// Output: 0

// Constraints:
// 1 <= nums.length <= 50
// 1 <= nums[i] <= 50

/* My Solution */

using System.Linq;

public class Solution
{
    public int MinimumOperations(int[] nums)
    {
        return nums.Count(num => num % 3 != 0);
    }
}
