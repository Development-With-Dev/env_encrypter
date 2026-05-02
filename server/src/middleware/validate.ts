import { body, param, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export function handleValidationErrors(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      error: 'Validation failed',
      details: errors.array().map((e) => ({
        field: 'path' in e ? e.path : 'unknown',
        message: e.msg,
      })),
    });
    return;
  }
  next();
}

export const validateCreateSecret = [
  body('encryptedData')
    .isString()
    .notEmpty()
    .isLength({ max: 68_000 })
    .withMessage('Encrypted data must be a string with max 68,000 characters'),

  body('iv')
    .isString()
    .notEmpty()
    .isLength({ min: 8, max: 24 })
    .withMessage('IV must be a valid base64 string (12 bytes)'),

  body('salt')
    .optional()
    .isString()
    .isLength({ min: 8, max: 48 })
    .withMessage('Salt must be a valid base64 string (up to 32 bytes)'),

  body('isPasswordProtected')
    .isBoolean()
    .withMessage('isPasswordProtected must be a boolean'),

  body('maxViews')
    .optional({ nullable: true })
    .isInt({ min: 1, max: 100 })
    .withMessage('maxViews must be between 1 and 100'),

  body('expiresIn')
    .isInt({ min: 300, max: 604_800 })
    .withMessage('expiresIn must be between 300 (5 min) and 604800 (7 days) seconds'),

  handleValidationErrors,
];

export const validateAccessToken = [
  param('token')
    .matches(/^[a-f0-9]{64}$/)
    .withMessage('Invalid access token format'),

  handleValidationErrors,
];
